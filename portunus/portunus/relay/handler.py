"""WebSocket relay handler.

Manages the full lifecycle of a WebSocket relay connection:
authentication, upstream connection, bidirectional message relay,
and per-message logging to the existing Kinesis body streams.
"""

import asyncio
import logging
import time
from dataclasses import dataclass

import websockets
from starlette.websockets import WebSocket, WebSocketDisconnect

from portunus.config import config
from portunus.relay import WsCloseCode
from portunus.relay.auth import WsAuthResult, authenticate_ws
from portunus.relay.logger import enqueue_log, log_ws_headers, log_ws_summary
from portunus.services.auth_service import AuthService
from portunus.services.publish_service import PublishService
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")

# Headers NOT forwarded from client upgrade request to upstream.
# Everything else passes through — avoids maintaining an allowlist
# that would need updating for every new client/provider.
_BLOCKED_HEADERS = frozenset(
    {
        # Hop-by-hop (handled by websockets library on new connection)
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        # Auth (replaced with real API key)
        "authorization",
        # Routing (specific to this proxy, not the upstream)
        "host",
        # Proxy headers (could spoof source identity at upstream)
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    }
)
_BLOCKED_HEADER_PREFIXES = ("x-portunus-",)


@dataclass
class UpstreamTarget:
    """Parsed upstream target from Envoy-injected headers."""

    host: str
    port: int
    use_tls: bool


def _parse_target(websocket: WebSocket, request_id: str) -> UpstreamTarget | None:
    """Extract upstream target from Envoy-injected headers.

    Returns None and closes the WebSocket if headers are missing/invalid.
    """
    host = websocket.headers.get("x-portunus-target-host")
    if not host:
        logger.error(f"WS {request_id}: x-portunus-target-host header missing")
        return None

    try:
        port = int(websocket.headers.get("x-portunus-target-port", "443"))
    except ValueError:
        logger.error(f"WS {request_id}: Invalid target port")
        return None

    use_tls = (
        websocket.headers.get("x-portunus-target-use-tls", "true").lower() == "true"
    )
    return UpstreamTarget(host=host, port=port, use_tls=use_tls)


def _build_upstream_headers(websocket: WebSocket, api_key: str) -> dict[str, str]:
    """Build headers for the upstream connection.

    Forwards all client headers except blocked ones, and replaces
    the Authorization header with the real API key.
    """
    headers = {"Authorization": f"Bearer {api_key}"}
    for key, value in websocket.headers.items():
        if key in _BLOCKED_HEADERS:
            continue
        if any(key.startswith(p) for p in _BLOCKED_HEADER_PREFIXES):
            continue
        headers[key] = value
    return headers


def _build_upstream_uri(target: UpstreamTarget, path: str, websocket: WebSocket) -> str:
    """Build the upstream WebSocket URI with query string."""
    scheme = "wss" if target.use_tls else "ws"
    uri = f"{scheme}://{target.host}:{target.port}/{path}"
    query_string = websocket.scope.get("query_string", b"").decode("utf-8")
    if query_string:
        uri += f"?{query_string}"
    return uri


async def _connect_upstream(
    target: UpstreamTarget,
    path: str,
    websocket: WebSocket,
    api_key: str,
    request_id: str,
    max_message_size: int,
) -> websockets.WebSocketClientProtocol | None:
    """Connect to the upstream WebSocket.

    Returns None if the connection fails.
    """
    uri = _build_upstream_uri(target, path, websocket)
    headers = _build_upstream_headers(websocket, api_key)

    try:
        upstream = await websockets.connect(
            uri,
            extra_headers=headers,
            max_size=max_message_size,
            open_timeout=10,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to connect upstream: {e}")
        return None

    logger.info(f"WS {request_id}: Upstream connected to {uri}")
    return upstream


async def _publish_connection_metadata(
    publish_service: PublishService,
    websocket: WebSocket,
    ws_auth: WsAuthResult,
    request_id: str,
    upstream_host: str,
) -> None:
    """Log upgrade headers and publish metadata on connection open."""
    # Log upgrade request headers (parity with HTTP header logging).
    # Strip internal headers and authorization (contains encoded AWS credentials).
    upgrade_headers = {
        k: v
        for k, v in websocket.headers.items()
        if not k.startswith("x-portunus-") and k != "authorization"
    }
    # Include upstream authority so downstream consumers can identify
    # which API provider handled the request.
    upgrade_headers["authority"] = upstream_host
    await log_ws_headers(publish_service, request_id, upgrade_headers)

    # Publish metadata
    try:
        await publish_service.publish_metadata(
            request_id=request_id,
            timestamp=generate_iso_timestamp(),
            principal_info=ws_auth.auth_result.principal_info.to_dict(),
            secret_arn=ws_auth.secret_arn,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to publish metadata: {e}")


async def _relay(
    websocket: WebSocket,
    upstream: websockets.WebSocketClientProtocol,
    publish_service: PublishService,
    request_id: str,
    max_lifetime: int,
) -> tuple[int, int, WsCloseCode]:
    """Run bidirectional message relay with per-message logging.

    Returns (client_msg_count, upstream_msg_count, close_code).
    """
    client_msg_index = 0
    upstream_msg_index = 0

    async def client_to_upstream() -> None:
        nonlocal client_msg_index
        try:
            while True:
                msg = await websocket.receive()
                msg_type = msg.get("type", "")
                if msg_type == "websocket.disconnect":
                    break

                text = msg.get("text")
                data_bytes = msg.get("bytes")

                if text is not None:
                    message_bytes = text.encode("utf-8")
                    await upstream.send(text)
                elif data_bytes is not None:
                    message_bytes = data_bytes
                    await upstream.send(data_bytes)
                else:
                    break

                await enqueue_log(
                    publish_service,
                    request_id,
                    "client_to_upstream",
                    message_bytes,
                    client_msg_index,
                )
                client_msg_index += 1
        except WebSocketDisconnect:
            logger.info(f"WS {request_id}: Client disconnected")
        except Exception as e:
            logger.error(f"WS {request_id}: Client->upstream error: {e}")

    async def upstream_to_client() -> None:
        nonlocal upstream_msg_index
        try:
            async for raw_message in upstream:
                if isinstance(raw_message, bytes):
                    message_bytes = raw_message
                    await websocket.send_bytes(message_bytes)
                else:
                    message_bytes = raw_message.encode("utf-8")
                    await websocket.send_text(raw_message)

                await enqueue_log(
                    publish_service,
                    request_id,
                    "upstream_to_client",
                    message_bytes,
                    upstream_msg_index,
                )
                upstream_msg_index += 1
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"WS {request_id}: Upstream disconnected")
        except Exception as e:
            logger.error(f"WS {request_id}: Upstream->client error: {e}")

    close_code = WsCloseCode.NORMAL
    tasks: list[asyncio.Task] = [
        asyncio.create_task(client_to_upstream(), name=f"ws-{request_id}-c2u"),
        asyncio.create_task(upstream_to_client(), name=f"ws-{request_id}-u2c"),
    ]
    try:
        async with asyncio.timeout(max_lifetime):
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except TimeoutError:
        close_code = WsCloseCode.GOING_AWAY
        logger.info(
            f"WS {request_id}: Connection lifetime limit reached ({max_lifetime}s)"
        )
    except asyncio.CancelledError:
        close_code = WsCloseCode.GOING_AWAY
        logger.info(f"WS {request_id}: Connection cancelled (server draining)")
    finally:
        # Always cancel any still-running relay task so it cannot
        # continue to read/write after we return. Without this, an
        # outer cancel (e.g. lifespan drain) would orphan the inner
        # tasks and they'd keep running against a closing socket.
        for task in tasks:
            if not task.done():
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # `gather(return_exceptions=True)` absorbs everything; surface
        # non-cancellation Exceptions so a genuine bug in the inner
        # tasks isn't invisible. The inner coroutines already log their
        # own expected exceptions (WebSocketDisconnect, ConnectionClosed),
        # so anything reaching here is unexpected. We deliberately do
        # not catch BaseException — KeyboardInterrupt / SystemExit
        # should propagate.
        for task, result in zip(tasks, results):
            if result is None or isinstance(result, asyncio.CancelledError):
                continue
            if isinstance(result, Exception):
                logger.error(
                    f"WS {request_id}: {task.get_name()} raised unexpectedly: "
                    f"{result!r}"
                )

    return client_msg_index, upstream_msg_index, close_code


async def handle_ws_connection(
    websocket: WebSocket,
    path: str,
    auth_service: AuthService,
    publish_service: PublishService,
    request_id: str,
) -> None:
    """Handle a WebSocket relay connection.

    Orchestrates the connection lifecycle: parse target, authenticate,
    connect upstream, relay messages, log, and clean up.
    """
    relay_config = config.relay

    # Parse target from Envoy-injected headers
    target = _parse_target(websocket, request_id)
    if target is None:
        try:
            await websocket.close(
                code=WsCloseCode.INTERNAL_ERROR,
                reason="WebSocket relay not configured",
            )
        except Exception:
            pass
        return

    # Authenticate before accepting
    ws_auth = await authenticate_ws(websocket, auth_service, request_id, target.host)
    if ws_auth is None:
        return

    # Accept and connect upstream
    await websocket.accept()
    connection_start = time.monotonic()
    logger.info(
        f"WS {request_id}: Connection accepted, connecting upstream " f"to /{path}"
    )

    await _publish_connection_metadata(
        publish_service, websocket, ws_auth, request_id, target.host
    )

    upstream = await _connect_upstream(
        target,
        path,
        websocket,
        ws_auth.api_key,
        request_id,
        relay_config.max_message_size,
    )
    if upstream is None:
        await websocket.close(
            code=WsCloseCode.INTERNAL_ERROR,
            reason="Upstream connection failed",
        )
        return

    # Relay messages
    client_msgs, upstream_msgs, close_code = await _relay(
        websocket,
        upstream,
        publish_service,
        request_id,
        relay_config.max_connection_lifetime,
    )

    # Log summary and clean up
    duration = time.monotonic() - connection_start

    # Shield the summary publish against re-cancellation. In the normal
    # Phase-2 flow `_relay` already absorbed the single cancel, so this
    # shield is a no-op. It only matters under uvicorn-level escalation
    # (a second cancel after the lifespan returns), where we still want
    # the session summary row to reach the response-headers Kinesis
    # stream — downstream consumers key WS sessions on that row, so
    # dropping it would orphan every per-message body chunk.
    try:
        await asyncio.shield(
            log_ws_summary(
                publish_service,
                request_id,
                client_msgs,
                upstream_msgs,
                duration,
            )
        )
    except asyncio.CancelledError:
        logger.info(f"WS {request_id}: summary publish shielded past cancel")
        raise
    except Exception as e:  # defensive — log_ws_summary already catches
        logger.error(f"WS {request_id}: summary publish failed: {e}")

    try:
        await upstream.close()
    except Exception as e:
        logger.debug(
            f"WS {request_id}: upstream close error (expected on drain): {e!r}"
        )
    try:
        await websocket.close(code=close_code)
    except Exception as e:
        logger.debug(f"WS {request_id}: client close error (expected on drain): {e!r}")

    logger.info(
        f"WS {request_id}: Connection closed after {duration:.1f}s. "
        f"Messages: {client_msgs} client, {upstream_msgs} upstream"
    )
