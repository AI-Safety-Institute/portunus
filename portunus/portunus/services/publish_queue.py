"""Bounded async publish queue with tiered drop policy + opportunistic batching.

``submit_blocking`` (headers/trailers) uses normal asyncio backpressure;
``submit_droppable`` (high-volume bodies) is bounded by both ``body_capacity``
records AND ``max_bytes`` retained payload bytes — each queued body task pins
its raw chunk by closure, so a count-only cap would allow ~GBs retained.

Workers block for one item then drain only what's ALREADY queued
(``get_nowait``) up to ``max_batch``, shipping one Firehose ``PutRecordBatch``
per stream. The batch is a subset of the bounded queue, so it adds no unbounded
buffer.

Accounting invariant (checkable once ``stop()`` returns)::

    submitted_total == published_total + dropped_total + build_failed_total
                       + delivery_failed_total + skipped_unconfigured_total
                       + cancelled_total

``submitted_total`` counts every submit attempt, so drain-time loss reconciles:
anything accepted but not on a terminal counter is folded into
``cancelled_total`` at stop — including in-flight-batch records a plain
``qsize()`` misses. A sentinel that itself can't be enqueued counts on
``sentinel_dropped_total`` only (never ``dropped_total``), so one lost chunk
increments ``dropped_total`` exactly once.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, List, Optional

logger = logging.getLogger("api.access")

# Ships one stream's built records; returns the count Firehose did NOT accept.
# Matches PublishService.put_record_batch.
BatchSender = Callable[[str, List[bytes]], Awaitable[int]]

# Cap on request_ids named in one delivery-failure log line (a batch spans
# up to max_batch records; the count still reports the full loss).
_MAX_LOGGED_IDS = 20


def _format_ids(ids: Optional[set[str]]) -> str:
    """Render a bounded, sorted sample of the request_ids in a failed batch."""
    if not ids:
        return "none-recorded"
    listed = sorted(ids)[:_MAX_LOGGED_IDS]
    suffix = f" +{len(ids) - len(listed)} more" if len(ids) > len(listed) else ""
    return ",".join(listed) + suffix


@dataclass
class PublishTask:
    """A queued audit record: a sync builder + a label for logging.

    ``build`` returns ``(stream_name, data_bytes)`` or ``None`` (stream not
    configured). It runs on the worker (off the ext_proc hot path); carrying
    the builder rather than a coroutine lets the worker group records by
    stream for batching.

    ``size_bytes`` is the payload the builder closure retains, charged against
    ``max_bytes`` while queued or in an in-flight batch. Metadata tasks may
    leave it 0.
    """

    build: Callable[[], Optional[tuple[str, bytes]]]
    label: str  # for logging — e.g. "request_body", "ws_frame"
    size_bytes: int = 0
    # Correlation id for failure logs. Workers run outside any request
    # context (they snapshot an empty contextvar context at startup), so the
    # id must travel with the task to be loggable when its record fails.
    request_id: Optional[str] = None


class BoundedPublishQueue:
    """Bounded asyncio queue with a drop-body / block-other tiering."""

    def __init__(
        self,
        *,
        maxsize: int,
        num_workers: int,
        batch_sender: BatchSender,
        body_capacity: Optional[int] = None,
        max_bytes: Optional[int] = None,
        max_batch: int = 500,
    ) -> None:
        if maxsize < 1:
            raise ValueError(f"maxsize must be >=1, got {maxsize}")
        if max_batch < 1:
            raise ValueError(f"max_batch must be >=1, got {max_batch}")
        if max_bytes is not None and max_bytes < 1:
            raise ValueError(f"max_bytes must be >=1, got {max_bytes}")
        self._queue: asyncio.Queue[Optional[PublishTask]] = asyncio.Queue(
            maxsize=maxsize
        )
        self._num_workers = num_workers
        self._batch_sender = batch_sender
        # Per-worker cap on already-queued items drained into one batch; a
        # subset of the queue, so no memory beyond maxsize.
        self._max_batch = max_batch
        self._workers: list[asyncio.Task] = []
        # Byte budget for retained payloads (queued + in-flight); None disables.
        self._max_bytes = max_bytes
        self._queued_bytes = 0
        # Every submit attempt, accepted or not — the reconciliation anchor
        # for the module-docstring invariant.
        self._submitted_total = 0
        self._dropped_total = 0
        self._published_total = 0
        # Distinct failure modes: build_failed = task.build() raised (local
        # bug); delivery_failed = Firehose rejected a built record (throttling/
        # outage, a capacity concern).
        self._build_failed_total = 0
        self._delivery_failed_total = 0
        # build() returned None — target stream not configured (e.g.
        # FIREHOSE_WS_SUMMARY_STREAM unset). Counted so the skip is observable.
        self._skipped_unconfigured_total = 0
        # Drop sentinels that couldn't be enqueued (blocking submit timed out
        # under saturation). Off ``dropped_total`` so one lost chunk counts once.
        self._sentinel_dropped_total = 0
        # Accepted but never flushed because a drain timed out (e.g. wedged
        # Firehose sink at shutdown). Distinct from dropped_total (queue
        # pressure) and delivery_failed_total (Firehose rejection); this is
        # shutdown loss a clean exit would hide. Includes in-flight-batch
        # records, not just ``qsize()``. ``stop_grpc_server`` alarms on it.
        self._cancelled_total = 0

        # Default 90/10: bodies cap at 90% of maxsize, reserving headroom for
        # blocking metadata submits.
        if body_capacity is None:
            body_capacity = max(1, int(maxsize * 0.9))
        if body_capacity > maxsize:
            raise ValueError(
                f"body_capacity ({body_capacity}) must be <= maxsize ({maxsize})"
            )
        self._body_capacity = body_capacity

    @property
    def submitted_total(self) -> int:
        """Every submit attempt (accepted or dropped); reconciliation anchor.

        Equals the sum of the terminal counters after ``stop()`` (see the
        module docstring); a mismatch means silent loss.
        """
        return self._submitted_total

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
    def skipped_unconfigured_total(self) -> int:
        """Records skipped because their target stream isn't configured.

        Non-zero means an optional stream (e.g. ``FIREHOSE_WS_SUMMARY_STREAM``)
        is unset while records for it are produced — data discarded by config,
        not pressure or failure. Alarmable.
        """
        return self._skipped_unconfigured_total

    @property
    def sentinel_dropped_total(self) -> int:
        """Drop-sentinel submits that timed out under saturation.

        A lost gap marker, not a lost record (the record's loss is already on
        ``dropped_total``); the chunk_id gap is the downstream fallback signal.
        """
        return self._sentinel_dropped_total

    @property
    def cancelled_total(self) -> int:
        """Records accepted but never flushed when the pool stopped.

        Distinct from ``dropped_total`` (submit-time queue pressure) and
        ``delivery_failed_total`` (Firehose rejection); shutdown loss despite
        a clean exit — alarm on it. Includes in-flight-batch records.
        """
        return self._cancelled_total

    @property
    def failed_total(self) -> int:
        """All failures (build + delivery), for log back-compat.

        Distinct from ``dropped_total`` (queue-pressure drops). Prefer the
        component counters to tell a code bug from a Firehose capacity problem.
        """
        return self._build_failed_total + self._delivery_failed_total

    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def queued_bytes(self) -> int:
        """Raw payload bytes retained by queued + in-flight tasks."""
        return self._queued_bytes

    def _accounted_total(self) -> int:
        """Sum of the terminal counters (see the invariant in the docstring)."""
        return (
            self._published_total
            + self._dropped_total
            + self._build_failed_total
            + self._delivery_failed_total
            + self._skipped_unconfigured_total
            + self._cancelled_total
        )

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

        Sentinels go in via ``put`` (not ``put_nowait``) bounded by
        ``drain_timeout``: under a shutdown audit flood ``put_nowait`` would
        raise ``QueueFull`` and abort the shutdown path, so instead a timeout
        cancels the workers directly.

        Returns the count of accepted records never flushed (0 on a clean
        drain), derived from the ``submitted_total`` reconciliation, NOT
        ``qsize()`` — which misses in-flight-batch records and counts the
        shutdown sentinels. Callers log it so shutdown loss is observable.
        """
        cancelled_before = self._cancelled_total
        timed_out = False
        try:
            async with asyncio.timeout(drain_timeout):
                for _ in self._workers:
                    await self._queue.put(None)
                await asyncio.gather(*self._workers, return_exceptions=True)
        except TimeoutError:
            timed_out = True
            for w in self._workers:
                w.cancel()
            # Workers cancelled mid-flush count their in-flight records on
            # ``cancelled_total`` in their CancelledError handler.
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

        # Reconcile: any accepted record not on a terminal counter was lost
        # (still queued, in an unseen in-flight batch, or submitted post-exit).
        # A negative residue is a double-count bug making every figure
        # untrustworthy — alarm rather than swallow it.
        unaccounted = self._submitted_total - self._accounted_total()
        if unaccounted > 0:
            self._cancelled_total += unaccounted
        elif unaccounted < 0:
            logger.error(
                "Audit counter reconciliation failed: terminal counters "
                "exceed submitted_total by %d (published=%d dropped=%d "
                "build_failed=%d delivery_failed=%d skipped_unconfigured=%d "
                "cancelled=%d vs submitted=%d) — a double-count bug; "
                "publish/drop totals are not trustworthy",
                -unaccounted,
                self._published_total,
                self._dropped_total,
                self._build_failed_total,
                self._delivery_failed_total,
                self._skipped_unconfigured_total,
                self._cancelled_total,
                self._submitted_total,
                extra={
                    "event": "audit_counter_mismatch",
                    "over_accounted": -unaccounted,
                },
            )

        cancelled = self._cancelled_total - cancelled_before
        if timed_out:
            logger.warning(
                "Publish workers did not drain within %.1fs; cancelling "
                "(%d records unflushed, in-flight batches included)",
                drain_timeout,
                cancelled,
            )
        return cancelled

    async def submit_blocking(
        self,
        task: PublishTask,
        *,
        timeout: Optional[float] = None,
        sentinel: bool = False,
    ) -> bool:
        """Submit with normal asyncio backpressure — for headers/trailers.

        With ``timeout`` set, gives up rather than block forever on a saturated
        queue; the timed-out record counts on ``dropped_total`` (or
        ``sentinel_dropped_total`` when ``sentinel=True`` — see the class
        docstring). Returns True when enqueued.
        """
        try:
            if timeout is None:
                await self._queue.put(task)
            else:
                async with asyncio.timeout(timeout):
                    await self._queue.put(task)
        except TimeoutError:
            if sentinel:
                self._sentinel_dropped_total += 1
            else:
                self._submitted_total += 1
                self._dropped_total += 1
            logger.warning(
                "Blocking publish submit timed out after %.1fs (%s%s)",
                timeout if timeout is not None else 0.0,
                task.label,
                "; chunk_id gap is the fallback drop signal" if sentinel else "",
            )
            return False
        self._submitted_total += 1
        self._queued_bytes += task.size_bytes
        return True

    def submit_droppable(self, task: PublishTask) -> bool:
        """Submit with drop-on-full semantics — for body records.

        Drops when the queue holds ``body_capacity`` items (soft cap reserving
        headroom for blocking submits), when the payload would exceed the
        ``max_bytes`` budget (count alone doesn't cap retained bytes), or when
        ``put_nowait`` races (hard cap). Returns True on accept.
        """
        self._submitted_total += 1
        if self._queue.qsize() >= self._body_capacity:
            self._dropped_total += 1
            return False
        if (
            self._max_bytes is not None
            and self._queued_bytes + task.size_bytes > self._max_bytes
        ):
            self._dropped_total += 1
            return False
        try:
            self._queue.put_nowait(task)
        except asyncio.QueueFull:
            self._dropped_total += 1
            return False
        self._queued_bytes += task.size_bytes
        return True

    async def _worker_loop(self) -> None:
        """Drain the queue in stream-grouped batches until a sentinel arrives.

        Blocks for one item, drains up to ``max_batch`` more already-queued
        (never awaits), groups by stream, ships one ``batch_sender`` per
        stream. A sentinel seen mid-drain flushes first, then stops.
        """
        while True:
            first = await self._queue.get()
            if first is None:
                self._queue.task_done()
                return

            tasks: list[PublishTask] = [first]
            stop = False
            # Pull only what's already buffered — no await, so the batch can't
            # exceed what the bounded queue holds.
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
                # One task_done per real task. Byte budget released only after
                # the flush, so ``queued_bytes`` bounds in-flight memory too.
                for task in tasks:
                    self._queued_bytes -= task.size_bytes
                    self._queue.task_done()

            if stop:
                return

    async def _flush_batch(self, tasks: list[PublishTask]) -> None:
        """Build, group by stream, and ship a batch of tasks.

        Cancellation-aware: a drain timeout cancels workers mid-send and this
        batch is invisible to ``qsize()``, so on ``CancelledError`` every
        unconfirmed record is counted on ``cancelled_total`` before re-raising.
        """
        # Build (sync) and group by stream; None means unconfigured — count it.
        by_stream: dict[str, list[bytes]] = {}
        ids_by_stream: dict[str, set[str]] = {}
        for task in tasks:
            try:
                result = task.build()
            except Exception as e:
                logger.error(
                    "Build failed for %s (request_id=%s): %s",
                    task.label,
                    task.request_id,
                    type(e).__name__,
                )
                self._build_failed_total += 1
                continue
            if result is None:
                self._skipped_unconfigured_total += 1
                continue
            stream_name, data = result
            by_stream.setdefault(stream_name, []).append(data)
            if task.request_id:
                ids_by_stream.setdefault(stream_name, set()).add(task.request_id)

        unconfirmed = sum(len(records) for records in by_stream.values())
        try:
            for stream_name, records in by_stream.items():
                try:
                    failed = await self._batch_sender(stream_name, records)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # batch_sender is contracted not to raise, but guard anyway.
                    logger.error(
                        "Batch send to %s raised: %s (request_ids=%s)",
                        stream_name,
                        type(e).__name__,
                        _format_ids(ids_by_stream.get(stream_name)),
                    )
                    failed = len(records)
                self._published_total += len(records) - failed
                self._delivery_failed_total += failed
                unconfirmed -= len(records)
        except asyncio.CancelledError:
            # Cancelled mid-flight: count whatever the sender never confirmed
            # (conservatively including the in-flight group) so loss reconciles.
            self._cancelled_total += unconfirmed
            raise
