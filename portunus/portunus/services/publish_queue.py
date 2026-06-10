"""Bounded async publish queue with tiered drop policy.

Header/trailer submits use ``submit_blocking`` (normal asyncio
backpressure); high-volume body submits use ``submit_droppable`` and
are bounded by ``body_capacity`` so a body flood cannot starve a
blocking metadata submit.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger("api.access")


@dataclass
class PublishTask:
    """A queued work item describing one publish call."""

    coro_fn: Callable[[], Awaitable[Any]]
    label: str  # for logging — e.g. "request_body", "ws_frame"


class BoundedPublishQueue:
    """Bounded asyncio queue with a drop-body / block-other tiering."""

    def __init__(
        self,
        *,
        maxsize: int,
        num_workers: int,
        body_capacity: Optional[int] = None,
    ) -> None:
        if maxsize < 1:
            raise ValueError(f"maxsize must be >=1, got {maxsize}")
        self._queue: asyncio.Queue[Optional[PublishTask]] = asyncio.Queue(
            maxsize=maxsize
        )
        self._num_workers = num_workers
        self._workers: list[asyncio.Task] = []
        self._dropped_total = 0
        self._published_total = 0
        self._failed_total = 0

        # Default 90/10 split: bodies cap at 90% of maxsize, reserving
        # 10% headroom for blocking metadata submits.
        if body_capacity is None:
            body_capacity = max(1, int(maxsize * 0.9))
        if body_capacity > maxsize:
            raise ValueError(
                f"body_capacity ({body_capacity}) must be <= maxsize ({maxsize})"
            )
        self._body_capacity = body_capacity

    @property
    def dropped_total(self) -> int:
        return self._dropped_total

    @property
    def published_total(self) -> int:
        return self._published_total

    @property
    def failed_total(self) -> int:
        """Tasks whose ``coro_fn`` raised — Firehose API errors etc.

        Distinct from ``dropped_total`` (queue-pressure drops before the
        task ever ran). Failures here are records portunus accepted into
        the queue but couldn't deliver to Firehose.
        """
        return self._failed_total

    def qsize(self) -> int:
        return self._queue.qsize()

    async def start(self) -> None:
        """Spawn the worker pool. Idempotent."""
        if self._workers:
            return
        for i in range(self._num_workers):
            self._workers.append(
                asyncio.create_task(self._worker_loop(), name=f"publish-worker-{i}")
            )

    async def stop(self, *, drain_timeout: float = 5.0) -> int:
        """Stop the worker pool, draining up to ``drain_timeout``.

        Sentinels are inserted via ``put`` (not ``put_nowait``) bounded
        by ``drain_timeout`` so that a queue saturated by an audit
        flood at shutdown — the exact moment ``put_nowait`` would
        raise ``QueueFull`` and abort the rest of the shutdown path —
        is handled by cancelling the workers directly rather than by
        letting the exception escape.

        Returns the number of audit records still queued (i.e. accepted
        but never flushed) when the drain timed out — 0 on a clean drain.
        Callers log this so shutdown record loss is observable rather than
        silent.
        """
        try:
            async with asyncio.timeout(drain_timeout):
                for _ in self._workers:
                    await self._queue.put(None)
                await asyncio.gather(*self._workers, return_exceptions=True)
        except TimeoutError:
            # Records still queued when we gave up — accepted but never
            # flushed — so the caller can report the loss.
            unflushed = self._queue.qsize()
            logger.warning(
                "Publish workers did not drain within %.1fs; cancelling "
                "(%d records unflushed)",
                drain_timeout,
                unflushed,
            )
            for w in self._workers:
                w.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
            return unflushed
        self._workers.clear()
        return 0

    async def submit_blocking(self, task: PublishTask) -> None:
        """Submit with normal asyncio backpressure — for headers/trailers."""
        await self._queue.put(task)

    def submit_droppable(self, task: PublishTask) -> bool:
        """Submit with drop-on-full semantics — for body records.

        Drops when the queue holds ``body_capacity`` items (soft cap that
        reserves headroom for blocking submits) or when ``put_nowait``
        races with another producer (hard cap). Returns True on accept.
        """
        if self._queue.qsize() >= self._body_capacity:
            self._dropped_total += 1
            return False
        try:
            self._queue.put_nowait(task)
            return True
        except asyncio.QueueFull:
            self._dropped_total += 1
            return False

    async def _worker_loop(self) -> None:
        """Drain the queue until a sentinel arrives."""
        while True:
            task = await self._queue.get()
            if task is None:
                self._queue.task_done()
                return
            try:
                await task.coro_fn()
                self._published_total += 1
            except Exception as e:
                # Log type(e).__name__ only — boto/Firehose exceptions can
                # echo the payload (relayed user content on the WS path).
                logger.error("Publish failed for %s: %s", task.label, type(e).__name__)
                self._failed_total += 1
            finally:
                self._queue.task_done()
