"""WebSocket relay handler.

Manages the full lifecycle of a WebSocket relay connection:
authentication, upstream connection, bidirectional message relay,
and per-message logging to the existing Kinesis body streams.
"""

import asyncio
import logging

import websockets
from starlette.websockets import WebSocket, WebSocketDisconnect

from portunus.config import config
from portunus.relay.auth import authenticate_ws
from portunus.relay.logger import fire_and_forget_log
from portunus.services.auth_service import AuthService
from portunus.services.publish_service import PublishService
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")


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

    if not relay_config.target_host:
        logger.error(f"WS {request_id}: TARGET_HOST not configured, rejecting")
        await websocket.close(code=1011, reason="WebSocket relay not configured")
        return

    # Authenticate before accepting
    ws_auth = await authenticate_ws(
        websocket, auth_service, request_id, relay_config.target_host
    )
    if ws_auth is None:
        return

    # Accept the client connection
    await websocket.accept()
    logger.info(f"WS {request_id}: Connection accepted, connecting upstream to /{path}")

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

    # Build upstream URI
    scheme = "wss" if relay_config.use_tls else "ws"
    upstream_uri = (
        f"{scheme}://{relay_config.target_host}:{relay_config.target_port}/{path}"
    )

    # Connect upstream with real API key
    extra_headers = {"Authorization": f"Bearer {ws_auth.api_key}"}
    try:
        upstream = await websockets.connect(
            upstream_uri,
            extra_headers=extra_headers,
            max_size=relay_config.max_message_size,
            open_timeout=10,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to connect upstream: {e}")
        await websocket.close(code=1011, reason="Upstream connection failed")
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
                if "text" in msg:
                    data = msg["text"]
                    message_bytes = data.encode("utf-8")
                    await upstream.send(data)
                elif "bytes" in msg and msg["bytes"]:
                    message_bytes = msg["bytes"]
                    await upstream.send(message_bytes)
                else:
                    break

                fire_and_forget_log(
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

                fire_and_forget_log(
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
        logger.info(
            f"WS {request_id}: Connection lifetime limit reached "
            f"({relay_config.max_connection_lifetime}s)"
        )

    # Clean up
    try:
        await upstream.close()
    except Exception:
        pass
    try:
        await websocket.close(code=1000)
    except Exception:
        pass

    logger.info(
        f"WS {request_id}: Connection closed. "
        f"Messages: {client_msg_index} client, {upstream_msg_index} upstream"
    )
