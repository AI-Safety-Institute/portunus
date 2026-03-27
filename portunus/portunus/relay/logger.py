"""WebSocket message logging to Kinesis.

Logs each relayed WebSocket message to the existing request-body and
response-body Kinesis streams, reusing the same PublishService methods
as HTTP logging. Client-to-upstream messages go to request-body,
upstream-to-client messages go to response-body.
"""

import asyncio
import logging
from typing import Literal

from portunus.services.publish_service import PublishService
from portunus.util import chunk_body_data, generate_iso_timestamp

logger = logging.getLogger("api.access")

WsDirection = Literal["client_to_upstream", "upstream_to_client"]


async def log_ws_message(
    publish_service: PublishService,
    request_id: str,
    direction: WsDirection,
    message_data: bytes,
    message_index: int,
) -> None:
    """Log a WebSocket message to the appropriate Kinesis body stream.

    Client-to-upstream messages are published to the request-body stream.
    Upstream-to-client messages are published to the response-body stream.
    Messages are chunked if they exceed Kinesis record size limits.

    Args:
        publish_service: PublishService for Kinesis publishing.
        request_id: Unique connection identifier.
        direction: "client_to_upstream" or "upstream_to_client".
        message_data: Raw message bytes.
        message_index: Zero-based index of this message in the connection.
    """
    timestamp = generate_iso_timestamp()
    chunks = chunk_body_data(message_data)
    num_chunks = max(len(chunks), 1)

    if not chunks:
        chunks = [b""]

    publish = (
        publish_service.publish_request_body
        if direction == "client_to_upstream"
        else publish_service.publish_response_body
    )

    for chunk_id, chunk in enumerate(chunks):
        try:
            await publish(
                request_id=request_id,
                body_bytes=chunk,
                timestamp=timestamp,
                chunk_id=chunk_id,
                num_chunks=num_chunks,
            )
        except Exception as e:
            logger.error(
                f"WS {request_id}: Failed to log message chunk "
                f"{chunk_id}/{num_chunks}: {e}"
            )


async def log_ws_headers(
    publish_service: PublishService,
    request_id: str,
    headers: dict[str, str],
) -> None:
    """Log WebSocket upgrade request headers to the request-headers Kinesis stream.

    Called once at connection open to capture the initial handshake headers,
    maintaining parity with the HTTP flow which logs request headers.

    Args:
        publish_service: PublishService for Kinesis publishing.
        request_id: Unique connection identifier.
        headers: Dictionary of upgrade request headers.
    """
    timestamp = generate_iso_timestamp()
    try:
        await publish_service.publish_request_headers(
            request_id=request_id,
            headers=headers,
            timestamp=timestamp,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to log request headers: {e}")


async def log_ws_summary(
    publish_service: PublishService,
    request_id: str,
    client_messages: int,
    upstream_messages: int,
    duration_seconds: float,
) -> None:
    """Log WebSocket connection summary to the response-headers Kinesis stream.

    Called at connection close to record session stats, maintaining parity
    with the HTTP flow which logs response headers.

    Args:
        publish_service: PublishService for Kinesis publishing.
        request_id: Unique connection identifier.
        client_messages: Count of client-to-upstream messages.
        upstream_messages: Count of upstream-to-client messages.
        duration_seconds: Total connection duration.
    """
    timestamp = generate_iso_timestamp()
    summary = {
        "x-ws-client-messages": str(client_messages),
        "x-ws-upstream-messages": str(upstream_messages),
        "x-ws-duration-seconds": f"{duration_seconds:.1f}",
        "x-ws-type": "websocket-summary",
    }
    try:
        await publish_service.publish_response_headers(
            request_id=request_id,
            headers=summary,
            timestamp=timestamp,
        )
    except Exception as e:
        logger.error(f"WS {request_id}: Failed to log connection summary: {e}")


def fire_and_forget_log(
    publish_service: PublishService,
    request_id: str,
    direction: WsDirection,
    message_data: bytes,
    message_index: int,
) -> None:
    """Schedule message logging as a background task.

    Does not block the relay loop.

    Args:
        publish_service: PublishService for Kinesis publishing.
        request_id: Unique connection identifier.
        direction: "client_to_upstream" or "upstream_to_client".
        message_data: Raw message bytes.
        message_index: Zero-based message index.
    """
    asyncio.create_task(
        log_ws_message(
            publish_service,
            request_id,
            direction,
            message_data,
            message_index,
        )
    )
