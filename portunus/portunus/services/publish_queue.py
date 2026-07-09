"""Bounded async publish queue with tiered drop policy + opportunistic batching.

Header/trailer submits use ``submit_blocking`` (normal asyncio
backpressure); high-volume body submits use ``submit_droppable`` and
are bounded by ``body_capacity`` records AND ``max_bytes`` retained
payload bytes, so a body flood can neither starve a blocking metadata
submit nor balloon process memory (each queued body task retains its
raw chunk by closure — a count-only cap allows ~GBs of retained bytes).

Workers drain the queue in stream-grouped chunks and ship each group via one
Firehose ``PutRecordBatch`` (see ``batch_sender``). Batching is *opportunistic*:
a worker takes one item (blocking), then drains only what's ALREADY queued
(``get_nowait``) up to a cap — so the batch is a subset of the already-bounded
queue and adds no new unbounded buffer. Under low load a worker ships a
batch-of-one immediately; under burst it ships up to ``max_batch`` per call,
cutting Firehose records/s without growing memory.

Accounting invariant (checkable once ``stop()`` returns)::

    submitted_total == published_total + dropped_total + build_failed_total
                       + delivery_failed_total + skipped_unconfigured_total
                       + cancelled_total

``submitted_total`` counts every submit attempt (accepted or dropped), so
drain-time loss is *reconcilable*: anything accepted that never reached a
terminal counter is folded into ``cancelled_total`` when the pool stops —
including records a worker had already pulled into an in-flight batch, which
a plain ``qsize()`` count misses entirely. Drop sentinels are accounted like
any other record when accepted; a sentinel that itself cannot be enqueued is
counted on ``sentinel_dropped_total`` only (never ``dropped_total``), so one
logical lost chunk increments ``dropped_total`` exactly once.
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

    ``size_bytes`` is the payload size the builder closure retains (e.g.
    ``len(body_bytes)`` for body records) — the queue's byte accounting
    charges this against ``max_bytes`` while the task is queued or in an
    in-flight batch. Header/metadata tasks may leave it 0 (their retained
    payloads are negligible next to body chunks).
    """

    build: Callable[[], Optional[tuple[str, bytes]]]
    label: str  # for logging — e.g. "request_body", "ws_frame"
    size_bytes: int = 0


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
        # Per-worker cap on how many already-queued items to drain into one
        # batch. Bounded by Firehose's 500/call; the batch is a subset of the
        # queue so this adds no memory beyond the existing maxsize cap.
        self._max_batch = max_batch
        self._workers: list[asyncio.Task] = []
        # Byte budget for retained payloads (queued + in-flight batches).
        # ``None`` disables byte accounting (tests / non-body queues).
        self._max_bytes = max_bytes
        self._queued_bytes = 0
        # Every submit attempt, accepted or not — the reconciliation anchor
        # for the invariant in the module docstring. Without it, drain loss
        # is unquantifiable (nothing to check the terminal counters against).
        self._submitted_total = 0
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
        # build() returned None — the record's stream isn't configured (e.g.
        # FIREHOSE_WS_SUMMARY_STREAM unset, which the boot guard deliberately
        # does not require). Counted so an unconfigured-stream drop is
        # observable instead of a silent skip.
        self._skipped_unconfigured_total = 0
        # Drop *sentinels* that could not be enqueued (their blocking submit
        # timed out under true saturation). Kept off ``dropped_total`` so one
        # logical lost chunk counts exactly once there.
        self._sentinel_dropped_total = 0
        # Audit records accepted into the queue but cancelled (never
        # flushed) because a drain timed out — e.g. a wedged Firehose
        # sink at shutdown. Tracked separately from ``dropped_total``
        # (queue-pressure drops) and ``delivery_failed_total`` (Firehose
        # rejections): this is shutdown loss, and a clean process exit
        # would otherwise hide it. ``stop_grpc_server`` alarms on it.
        # Includes records in an in-flight worker batch at cancel time,
        # not just those still visible via ``qsize()``.
        self._cancelled_total = 0

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
    def submitted_total(self) -> int:
        """Every submit attempt (accepted or dropped), sentinel-accepts included.

        The reconciliation anchor: after ``stop()`` returns,
        ``submitted_total`` equals the sum of the terminal counters
        (published + dropped + build_failed + delivery_failed +
        skipped_unconfigured + cancelled). A mismatch means silent loss.
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

        Non-zero in a deployment means an optional stream (e.g.
        ``FIREHOSE_WS_SUMMARY_STREAM``) is unset while records for it are
        being produced — data is being discarded by configuration, not by
        pressure or failure. Alarmable on its own.
        """
        return self._skipped_unconfigured_total

    @property
    def sentinel_dropped_total(self) -> int:
        """Drop-sentinel submits that timed out under true saturation.

        Each of these is a lost *gap marker*, not a lost record (the record's
        own loss is already on ``dropped_total``); the chunk_id gap remains
        the fallback signal downstream.
        """
        return self._sentinel_dropped_total

    @property
    def cancelled_total(self) -> int:
        """Records accepted but never flushed when the pool stopped.

        Distinct from ``dropped_total`` (rejected at submit under queue
        pressure) and ``delivery_failed_total`` (built but rejected by
        Firehose). A non-zero value means audit was lost at shutdown
        despite a clean process exit — alarm on it. Includes records a
        worker had already pulled into an in-flight batch when the drain
        timed out (previously uncounted).
        """
        return self._cancelled_total

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

        Sentinels are inserted via ``put`` (not ``put_nowait``) bounded
        by ``drain_timeout`` so that a queue saturated by an audit
        flood at shutdown — the exact moment ``put_nowait`` would
        raise ``QueueFull`` and abort the rest of the shutdown path —
        is handled by cancelling the workers directly rather than by
        letting the exception escape.

        Returns the number of accepted audit records that were never
        flushed — 0 on a clean drain. The count is derived from the
        ``submitted_total`` reconciliation, NOT from ``qsize()``: a
        ``qsize()`` snapshot misses records a worker had already pulled
        into an in-flight batch (up to ``max_batch`` per worker) and
        wrongly includes the shutdown sentinels, so it both under- and
        over-counts. Callers log the return so shutdown record loss is
        observable rather than silent.
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
            # Workers cancelled mid-``_flush_batch`` count their in-flight
            # records on ``cancelled_total`` from their CancelledError
            # handler before this gather returns.
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

        # Reconcile: any accepted record not yet on a terminal counter was
        # lost — still queued at cancel time, in a batch the CancelledError
        # accounting couldn't see, or submitted after the workers exited.
        # A NEGATIVE residue (accounted > submitted) can't be repaired the
        # same way, but it is just as much a bug — a double-count would make
        # every published/dropped figure untrustworthy — so alarm on it
        # instead of silently swallowing it.
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

        With ``timeout`` set, gives up after that many seconds instead of
        blocking indefinitely on a saturated queue; the timed-out record is
        counted on ``dropped_total`` (or ``sentinel_dropped_total`` when
        ``sentinel=True`` — see the class docstring for why sentinels are
        accounted separately). Returns True when the task was enqueued.
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

        Drops when the queue holds ``body_capacity`` items (soft cap that
        reserves headroom for blocking submits), when accepting the task's
        payload would exceed the ``max_bytes`` byte budget (the memory
        bound — record count alone doesn't cap retained bytes), or when
        ``put_nowait`` races with another producer (hard cap). Returns
        True on accept.
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
                # already accounted for). The byte budget is released only
                # here — after the flush — so ``queued_bytes`` bounds
                # retained memory including in-flight batches.
                for task in tasks:
                    self._queued_bytes -= task.size_bytes
                    self._queue.task_done()

            if stop:
                return

    async def _flush_batch(self, tasks: list[PublishTask]) -> None:
        """Build, group-by-stream, and ship a batch of tasks.

        Cancellation-aware: a drain timeout cancels workers mid-send, and
        the records of this batch are invisible to ``qsize()`` — so on
        ``CancelledError`` every record not yet confirmed by the sender is
        counted on ``cancelled_total`` before re-raising. Without this the
        in-flight loss (up to ``max_batch`` × workers per drain) hits no
        counter at all.
        """
        # Build records (sync serialization) and group by stream. A build
        # returning None means the stream isn't configured — count the skip.
        by_stream: dict[str, list[bytes]] = {}
        for task in tasks:
            try:
                result = task.build()
            except Exception as e:
                logger.error("Build failed for %s: %s", task.label, type(e).__name__)
                self._build_failed_total += 1
                continue
            if result is None:
                self._skipped_unconfigured_total += 1
                continue
            stream_name, data = result
            by_stream.setdefault(stream_name, []).append(data)

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
                        "Batch send to %s raised: %s", stream_name, type(e).__name__
                    )
                    failed = len(records)
                self._published_total += len(records) - failed
                self._delivery_failed_total += failed
                unconfirmed -= len(records)
        except asyncio.CancelledError:
            # Cancelled mid-flight (drain timeout): whatever the sender never
            # confirmed is lost. Count it — conservatively including the group
            # being sent when the cancel landed — so drain loss reconciles.
            self._cancelled_total += unconfirmed
            raise
