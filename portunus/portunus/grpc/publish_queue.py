"""Bounded async publish queue with tiered drop policy.

The Process service ships ext_proc observations to Kinesis via this queue.
The design has three concerns sharing the queue with different policies:

- Auth metadata is published synchronously in the Check service and never
  reaches this queue — it's the strongest guarantee in the pipeline.

- Header / trailer records are low-volume; the queue applies normal
  asyncio backpressure (``put``) so they never drop. If Kinesis falls
  behind for headers, the ext_proc stream's flow control naturally
  applies, but only briefly — header volume is tiny.

- Body records (HTTP body chunks, WS frame summaries) are high-volume.
  The queue applies a **drop-on-full** policy via ``put_nowait`` —
  backpressuring customer traffic to publish logs is worse than a
  logging gap, so we drop bodies and increment the
  ``logs_dropped_total`` metric instead.

A small worker pool drains the queue and invokes :class:`PublishService`
methods. Workers are awaited on shutdown so in-flight publishes finish.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger("api.access")


@dataclass
class PublishTask:
    """A queued work item describing one publish call.

    ``coro_fn`` returns an awaitable when called. Wrapping the publish
    call rather than the coroutine lets workers retry / log without
    holding a reference to an already-awaited coroutine.
    """

    coro_fn: Callable[[], Awaitable[Any]]
    label: str  # for logging — e.g. "request_body", "ws_frame"


class BoundedPublishQueue:
    """Bounded asyncio queue with a drop-body / block-other tiering."""

    def __init__(self, *, maxsize: int, num_workers: int) -> None:
        self._queue: asyncio.Queue[Optional[PublishTask]] = asyncio.Queue(
            maxsize=maxsize
        )
        self._num_workers = num_workers
        self._workers: list[asyncio.Task] = []
        self._dropped_total = 0
        self._published_total = 0

    @property
    def dropped_total(self) -> int:
        return self._dropped_total

    @property
    def published_total(self) -> int:
        return self._published_total

    def qsize(self) -> int:
        """Current queue depth — convenience for tests that drain on size."""
        return self._queue.qsize()

    async def start(self) -> None:
        """Spawn the worker pool. Idempotent — calling twice is a no-op."""
        if self._workers:
            return
        for i in range(self._num_workers):
            self._workers.append(
                asyncio.create_task(self._worker_loop(), name=f"publish-worker-{i}")
            )

    async def stop(self, *, drain_timeout: float = 5.0) -> None:
        """Stop the worker pool, draining in-flight work up to ``drain_timeout``.

        Pushes a sentinel ``None`` per worker; workers exit on seeing it.
        Workers that don't exit within the timeout get cancelled.
        """
        for _ in self._workers:
            self._queue.put_nowait(None)
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._workers, return_exceptions=True),
                timeout=drain_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Publish workers did not drain within %.1fs; cancelling",
                drain_timeout,
            )
            for w in self._workers:
                w.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def submit_blocking(self, task: PublishTask) -> None:
        """Submit a publish task with normal asyncio backpressure.

        Use for low-volume records (headers, trailers) where dropping
        would skew the log shape unacceptably. If Kinesis falls behind,
        the caller waits in line.
        """
        await self._queue.put(task)

    def submit_droppable(self, task: PublishTask) -> bool:
        """Submit a publish task with drop-on-full semantics.

        Use for high-volume body records. If the queue is full, the
        task is dropped and ``logs_dropped_total`` increments. Returns
        ``True`` on accept, ``False`` on drop.
        """
        try:
            self._queue.put_nowait(task)
            return True
        except asyncio.QueueFull:
            self._dropped_total += 1
            return False

    async def _worker_loop(self) -> None:
        """Drain the queue until a sentinel arrives.

        Publish failures are logged at error level but never re-raised —
        a single bad record shouldn't take a worker out of the pool.
        """
        while True:
            task = await self._queue.get()
            if task is None:
                self._queue.task_done()
                return
            try:
                await task.coro_fn()
                self._published_total += 1
            except Exception as e:
                # Log the exception class only — boto3/Kinesis errors can
                # echo the offending payload back in the exception message,
                # and on the WS path that payload is relayed user content
                # (token-bearing). Type name keeps the diagnostic without
                # leaking customer data into logs.
                logger.error("Publish failed for %s: %s", task.label, type(e).__name__)
            finally:
                self._queue.task_done()
