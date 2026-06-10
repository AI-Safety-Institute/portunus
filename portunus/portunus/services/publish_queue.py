"""Bounded async publish queue with tiered drop policy + opportunistic batching.

Header/trailer submits use ``submit_blocking`` (normal asyncio
backpressure); high-volume body submits use ``submit_droppable`` and
are bounded by ``body_capacity`` so a body flood cannot starve a
blocking metadata submit.

Workers drain the queue in stream-grouped chunks and ship each group via one
Firehose ``PutRecordBatch`` (see ``batch_sender``). Batching is *opportunistic*:
a worker takes one item (blocking), then drains only what's ALREADY queued
(``get_nowait``) up to a cap — so the batch is a subset of the already-bounded
queue and adds no new unbounded buffer. Under low load a worker ships a
batch-of-one immediately; under burst it ships up to ``max_batch`` per call,
cutting Firehose records/s without growing memory.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, List, Optional

logger = logging.getLogger("api.access")

# Ships one stream's worth of built records; returns the count Firehose did
# NOT accept. Matches PublishService.put_record_batch.
BatchSender = Callable[[str, List[bytes]], Awaitable[int]]


@dataclass
class PublishTask:
    """A queued audit record: a sync builder + a label for logging.

    ``build`` returns ``(stream_name, data_bytes)`` or ``None`` (stream not
    configured). It runs on the worker, not the ext_proc stream path, so
    serialization cost stays off the hot path. Carrying the builder (rather
    than a ready coroutine) lets the worker group records by stream for
    batching.
    """

    build: Callable[[], Optional[tuple[str, bytes]]]
    label: str  # for logging — e.g. "request_body", "ws_frame"


class BoundedPublishQueue:
    """Bounded asyncio queue with a drop-body / block-other tiering."""

    def __init__(
        self,
        *,
        maxsize: int,
        num_workers: int,
        batch_sender: BatchSender,
        body_capacity: Optional[int] = None,
        max_batch: int = 500,
    ) -> None:
        if maxsize < 1:
            raise ValueError(f"maxsize must be >=1, got {maxsize}")
        if max_batch < 1:
            raise ValueError(f"max_batch must be >=1, got {max_batch}")
        self._queue: asyncio.Queue[Optional[PublishTask]] = asyncio.Queue(
            maxsize=maxsize
        )
        self._num_workers = num_workers
        self._batch_sender = batch_sender
        # Per-worker cap on how many already-queued items to drain into one
        # batch. Bounded by Firehose's 500/call; the batch is a subset of the
        # queue so this adds no memory beyond the existing maxsize cap.
        self._max_batch = max_batch
        self._workers: list[asyncio.Task] = []
        self._dropped_total = 0
        self._published_total = 0
        # Two distinct failure modes with opposite remediations:
        #   _build_failed_total   — task.build() raised (a local serialization /
        #                            programming bug); fix the code.
        #   _delivery_failed_total — Firehose rejected/errored the record after
        #                            it was built (throttling, AWS outage); a
        #                            capacity/retry concern.
        self._build_failed_total = 0
        self._delivery_failed_total = 0

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
    def build_failed_total(self) -> int:
        """Records whose ``build()`` raised (local serialization/programming bug)."""
        return self._build_failed_total

    @property
    def delivery_failed_total(self) -> int:
        """Records built but rejected/errored by Firehose (throttling, outage)."""
        return self._delivery_failed_total

    @property
    def failed_total(self) -> int:
        """All failures (build + delivery), for back-compat with existing logs.

        Distinct from ``dropped_total`` (queue-pressure drops before the record
        was ever built). Prefer ``build_failed_total`` / ``delivery_failed_total``
        when you need to tell a code bug from a Firehose capacity problem.
        """
        return self._build_failed_total + self._delivery_failed_total

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
        """Drain the queue in stream-grouped batches until a sentinel arrives.

        Blocks for one item, then opportunistically drains up to
        ``max_batch`` more that are ALREADY queued (never awaits for more),
        groups them by target stream, and ships one ``batch_sender`` call per
        stream. A sentinel (None) seen mid-drain flushes the batch first, then
        stops.
        """
        while True:
            first = await self._queue.get()
            if first is None:
                self._queue.task_done()
                return

            tasks: list[PublishTask] = [first]
            stop = False
            # Greedily pull what's already buffered — no awaiting, so the
            # batch can't grow beyond what the bounded queue already holds.
            while len(tasks) < self._max_batch:
                try:
                    nxt = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if nxt is None:
                    # Shutdown sentinel: stop after flushing this batch.
                    self._queue.task_done()
                    stop = True
                    break
                tasks.append(nxt)

            try:
                await self._flush_batch(tasks)
            finally:
                # One task_done per real task pulled (the sentinel above is
                # already accounted for).
                for _ in tasks:
                    self._queue.task_done()

            if stop:
                return

    async def _flush_batch(self, tasks: list[PublishTask]) -> None:
        """Build, group-by-stream, and ship a batch of tasks."""
        # Build records (sync serialization) and group by stream. A build
        # returning None means the stream isn't configured — skip it.
        by_stream: dict[str, list[bytes]] = {}
        for task in tasks:
            try:
                result = task.build()
            except Exception as e:
                logger.error("Build failed for %s: %s", task.label, type(e).__name__)
                self._build_failed_total += 1
                continue
            if result is None:
                continue
            stream_name, data = result
            by_stream.setdefault(stream_name, []).append(data)

        for stream_name, records in by_stream.items():
            try:
                failed = await self._batch_sender(stream_name, records)
            except Exception as e:
                # batch_sender is contracted not to raise, but guard anyway.
                logger.error(
                    "Batch send to %s raised: %s", stream_name, type(e).__name__
                )
                failed = len(records)
            self._published_total += len(records) - failed
            self._delivery_failed_total += failed
