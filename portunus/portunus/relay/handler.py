"""WebSocket relay handler.

Manages the full lifecycle of a WebSocket relay connection:
authentication, upstream connection, bidirectional message relay,
and per-message logging to the existing Kinesis body streams.
"""

import asyncio
import logging
import time

import websockets
from starlette.websockets import WebSocket, WebSocketDisconnect

from portunus.config import config
from portunus.relay import WsCloseCode
from portunus.relay.auth import authenticate_ws
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
    }
)
_BLOCKED_HEADER_PREFIXES = ("x-portunus-",)


async def handle_ws_connection(
    websocket: WebSocket,
    path: str,
    auth_service: AuthService,
    publish_service: PublishService,
    request_id: str,
) -> None:
    """Handle a WebSocket relay connection.

    Authenticates the client, connects to the upstream WebSocket,
    and relays messages bidirectionally with per-message logging.

    Args:
        websocket: Client WebSocket connection (not yet accepted).
        path: The request path to forward upstream.
        auth_service: AuthService for authentication.
        publish_service: PublishService for Kinesis logging.
        request_id: Unique request/connection ID.
    """
    relay_config = config.relay

    # Read upstream target from headers injected by Envoy's request_headers_to_add.
    # Each proxy injects its own TARGET_HOST so Portunus knows where to connect.
    target_host = websocket.headers.get("x-portunus-target-host")
    if not target_host:
        logger.error(
            f"WS {request_id}: x-portunus-target-host header missing, rejecting"
        )
        try:
            await websocket.close(
                code=WsCloseCode.INTERNAL_ERROR,
                reason="WebSocket relay not configured",
            )
        except Exception:
            pass
        return

    try:
        target_port = int(websocket.headers.get("x-portunus-target-port", "443"))
    except ValueError:
        logger.error(f"WS {request_id}: Invalid target port, rejecting")
        try:
            await websocket.close(
                code=WsCloseCode.INTERNAL_ERROR,
                reason="Invalid target port",
            )
        except Exception:
            pass
        return
    use_tls = (
        websocket.headers.get("x-portunus-target-use-tls", "true").lower() == "true"
    )

    # Authenticate before accepting
    ws_auth = await authenticate_ws(websocket, auth_service, request_id, target_host)
    if ws_auth is None:
        return

    # Accept the client connection
    await websocket.accept()
    connection_start = time.monotonic()
    logger.info(f"WS {request_id}: Connection accepted, connecting upstream to /{path}")

    # Log upgrade request headers (parity with HTTP header logging)
    upgrade_headers = {
        k: v
        for k, v in websocket.headers.items()
        if not k.startswith("x-portunus-")  # strip internal headers
    }
    asyncio.create_task(log_ws_headers(publish_service, request_id, upgrade_headers))

    # Publish metadata
    try:
        timestamp = generate_iso_timestamp()
        principal_info = ws_auth.auth_result.principal_info.to_dict()
        await publish_service.publish_metadata(
            request_id=request_id,
            timestamp=timestamp,
            principal_info=principal_info,
            secret_arn=ws_auth.secret_arn,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to publish metadata: {e}")

    # Build upstream URI, preserving query string
    scheme = "wss" if use_tls else "ws"
    upstream_uri = f"{scheme}://{target_host}:{target_port}/{path}"
    query_string = websocket.scope.get("query_string", b"").decode("utf-8")
    if query_string:
        upstream_uri += f"?{query_string}"

    # Build upstream headers: real API key + all client headers except blocked
    upstream_headers = {"Authorization": f"Bearer {ws_auth.api_key}"}
    for key, value in websocket.headers.items():
        if key in _BLOCKED_HEADERS:
            continue
        if any(key.startswith(p) for p in _BLOCKED_HEADER_PREFIXES):
            continue
        upstream_headers[key] = value

    try:
        upstream = await websockets.connect(
            upstream_uri,
            extra_headers=upstream_headers,
            max_size=relay_config.max_message_size,
            open_timeout=10,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to connect upstream: {e}")
        await websocket.close(
            code=WsCloseCode.INTERNAL_ERROR,
            reason="Upstream connection failed",
        )
        return

    logger.info(f"WS {request_id}: Upstream connected to {upstream_uri}")

    # Relay messages bidirectionally
    client_msg_index = 0
    upstream_msg_index = 0

    async def client_to_upstream() -> None:
        """Relay messages from client to upstream."""
        nonlocal client_msg_index
        try:
            while True:
                msg = await websocket.receive()

                # Check message type explicitly to handle None values safely
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
        """Relay messages from upstream to client."""
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

    # Run both relay tasks with a lifetime timeout
    close_code = WsCloseCode.NORMAL
    try:
        async with asyncio.timeout(relay_config.max_connection_lifetime):
            tasks = [
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            ]
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
    except TimeoutError:
        close_code = WsCloseCode.GOING_AWAY
        logger.info(
            f"WS {request_id}: Connection lifetime limit reached "
            f"({relay_config.max_connection_lifetime}s)"
        )
    except asyncio.CancelledError:
        close_code = WsCloseCode.GOING_AWAY
        logger.info(f"WS {request_id}: Connection cancelled (server draining)")

    # Log connection summary (parity with HTTP response header logging)
    duration = time.monotonic() - connection_start
    await log_ws_summary(
        publish_service,
        request_id,
        client_msg_index,
        upstream_msg_index,
        duration,
    )

    # Clean up
    try:
        await upstream.close()
    except Exception:
        pass
    try:
        await websocket.close(code=close_code)
    except Exception:
        pass

    logger.info(
        f"WS {request_id}: Connection closed after {duration:.1f}s. "
        f"Messages: {client_msg_index} client, {upstream_msg_index} upstream"
    )
