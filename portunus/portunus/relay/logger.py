"""WebSocket message logging to Kinesis.

Logs each relayed WebSocket message to the existing request-body and
response-body Kinesis streams, reusing the same PublishService methods
as HTTP logging. Client-to-upstream messages go to request-body,
upstream-to-client messages go to response-body.

Uses a bounded asyncio queue with a fixed worker pool to decouple the
relay loop from Kinesis publish latency. The relay enqueues log items
without blocking; workers drain the queue in the background.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Literal

from portunus.services.publish_service import PublishService
from portunus.util import chunk_body_data, generate_iso_timestamp

logger = logging.getLogger("api.access")

WsDirection = Literal["client_to_upstream", "upstream_to_client"]


@dataclass
class _LogItem:
    """A queued message log entry."""

    publish_service: PublishService
    request_id: str
    direction: WsDirection
    message_data: bytes
    message_index: int


class LogQueue:
    """Bounded async queue with a fixed worker pool for Kinesis publishing.

    Decouples the relay loop from Kinesis latency — enqueue is non-blocking,
    workers publish concurrently up to ``num_workers``.
    """

    def __init__(self, num_workers: int = 200, max_queue_size: int = 10_000) -> None:
        self._queue: asyncio.Queue[_LogItem | None] = asyncio.Queue(
            maxsize=max_queue_size
        )
        self._num_workers = num_workers
        self._workers: list[asyncio.Task] = []

    async def start(self) -> None:
        """Spawn the worker pool."""
        for i in range(self._num_workers):
            self._workers.append(asyncio.create_task(self._worker(i)))

    async def stop(self) -> None:
        """Drain the queue and shut down workers."""
        # Send poison pills
        for _ in self._workers:
            await self._queue.put(None)
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def enqueue(self, item: _LogItem) -> None:
        """Enqueue a log item.

        If the queue is full, blocks until space is available. This applies
        backpressure to the relay loop rather than dropping log data.
        """
        await self._queue.put(item)

    async def _worker(self, worker_id: int) -> None:
        """Process log items from the queue."""
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            try:
                await _publish_message(item)
            except Exception as e:
                logger.error(f"WS {item.request_id}: Log worker {worker_id} error: {e}")
            finally:
                self._queue.task_done()


# Module-level singleton — initialised in app.py lifespan
_log_queue: LogQueue | None = None


def get_log_queue() -> LogQueue:
    """Get the module-level log queue (must be started first)."""
    assert _log_queue is not None, "LogQueue not started — call start_log_queue() first"
    return _log_queue


async def start_log_queue(num_workers: int = 200) -> None:
    """Create and start the global log queue."""
    global _log_queue
    _log_queue = LogQueue(num_workers=num_workers)
    await _log_queue.start()
    logger.info(f"WS log queue started with {num_workers} workers")


async def stop_log_queue() -> None:
    """Drain and stop the global log queue."""
    global _log_queue
    if _log_queue is not None:
        await _log_queue.stop()
        _log_queue = None
        logger.info("WS log queue stopped")


async def _publish_message(item: _LogItem) -> None:
    """Publish a single message to Kinesis."""
    timestamp = generate_iso_timestamp()
    chunks = chunk_body_data(item.message_data)
    num_chunks = max(len(chunks), 1)

    if not chunks:
        chunks = [b""]

    publish = (
        item.publish_service.publish_request_body
        if item.direction == "client_to_upstream"
        else item.publish_service.publish_response_body
    )

    for chunk_id, chunk in enumerate(chunks):
        try:
            await publish(
                request_id=item.request_id,
                body_bytes=chunk,
                timestamp=timestamp,
                chunk_id=chunk_id,
                num_chunks=num_chunks,
            )
        except Exception as e:
            logger.error(
                f"WS {item.request_id}: Failed to log message chunk "
                f"{chunk_id}/{num_chunks}: {e}"
            )


async def log_ws_message(
    publish_service: PublishService,
    request_id: str,
    direction: WsDirection,
    message_data: bytes,
    message_index: int,
) -> None:
    """Log a WebSocket message to the appropriate Kinesis body stream.

    Kept for direct-await usage (e.g. tests). For relay hot path,
    use fire_and_forget_log() which enqueues instead.
    """
    await _publish_message(
        _LogItem(
            publish_service=publish_service,
            request_id=request_id,
            direction=direction,
            message_data=message_data,
            message_index=message_index,
        )
    )


async def log_ws_headers(
    publish_service: PublishService,
    request_id: str,
    headers: dict[str, str],
) -> None:
    """Log WebSocket upgrade request headers to the request-headers Kinesis stream.

    Called once at connection open to capture the initial handshake headers,
    maintaining parity with the HTTP flow which logs request headers.
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


async def enqueue_log(
    publish_service: PublishService,
    request_id: str,
    direction: WsDirection,
    message_data: bytes,
    message_index: int,
) -> None:
    """Enqueue message logging.

    If the queue is full, applies backpressure (blocks until space
    is available) rather than dropping log data. If the log queue
    isn't running (e.g. in tests), publishes directly.
    """
    if _log_queue is not None:
        await _log_queue.enqueue(
            _LogItem(
                publish_service=publish_service,
                request_id=request_id,
                direction=direction,
                message_data=message_data,
                message_index=message_index,
            )
        )
    else:
        await log_ws_message(
            publish_service, request_id, direction, message_data, message_index
        )
