"""Tests for ``BoundedPublishQueue`` tiering: a body flood must not stall.

``submit_blocking`` (the header/trailer/ws-summary path) via the body_capacity reserve.
"""

from __future__ import annotations

import asyncio

import pytest

from portunus.services.publish_queue import BoundedPublishQueue, PublishTask


async def _noop_sender(stream_name: str, records: list[bytes]) -> int:
    """A batch_sender that accepts everything (0 failures)."""
    return 0


def _queue(**kwargs) -> BoundedPublishQueue:
    """BoundedPublishQueue with a default no-op batch_sender."""
    kwargs.setdefault("batch_sender", _noop_sender)
    return BoundedPublishQueue(**kwargs)


def _noop_task(label: str = "body") -> PublishTask:
    # build() returns (stream, bytes); the no-op sender ships it.
    return PublishTask(build=lambda: ("body", b"{}\n"), label=label)


@pytest.mark.asyncio
async def test_submit_droppable_drops_at_body_capacity_not_maxsize() -> None:
    """Soft cap protects metadata headroom above ``body_capacity``."""
    queue = _queue(
        maxsize=10,
        body_capacity=6,
        num_workers=0,
    )

    accepted = [queue.submit_droppable(_noop_task()) for _ in range(8)]
    assert accepted.count(True) == 6
    assert accepted.count(False) == 2
    assert queue.qsize() == 6
    assert queue.dropped_total == 2


@pytest.mark.asyncio
async def test_submit_blocking_does_not_wait_when_bodies_at_capacity() -> None:
    """With bodies filling the queue to ``body_capacity``, blocking metadata.

    submits slot into the reserve immediately rather than waiting on a worker.
    """
    queue = _queue(
        maxsize=10,
        body_capacity=6,
        num_workers=0,
    )

    for _ in range(6):
        assert queue.submit_droppable(_noop_task("body")) is True

    # Saturated for bodies, but four metadata slots remain; each
    # submit_blocking must complete without waiting for a worker.
    for _ in range(4):
        await asyncio.wait_for(
            queue.submit_blocking(_noop_task("header")),
            timeout=0.05,
        )

    assert queue.qsize() == 10


@pytest.mark.asyncio
async def test_default_body_capacity_is_ninety_percent_of_maxsize() -> None:
    """No explicit ``body_capacity`` reserves ~10% headroom by default."""
    queue = _queue(maxsize=100, num_workers=0)
    for _ in range(100):
        queue.submit_droppable(_noop_task())
    assert queue.qsize() == 90
    assert queue.dropped_total == 10


@pytest.mark.asyncio
async def test_body_capacity_above_maxsize_rejected() -> None:
    """Misconfiguration fails loudly at construction, not at the first submit."""
    with pytest.raises(ValueError):
        _queue(maxsize=10, body_capacity=11, num_workers=0)


@pytest.mark.asyncio
async def test_body_capacity_zero_drops_all_droppables_but_blocks_pass() -> None:
    """Edge: ``body_capacity=0`` disables body publishing but must not.

    deadlock metadata (blocking submits still pass).
    """
    queue = _queue(maxsize=4, body_capacity=0, num_workers=0)

    assert queue.submit_droppable(_noop_task()) is False
    assert queue.dropped_total == 1

    for _ in range(4):
        await asyncio.wait_for(
            queue.submit_blocking(_noop_task("header")),
            timeout=0.05,
        )
    assert queue.qsize() == 4


def _task(stream: str, label: str = "body") -> PublishTask:
    """A task whose build() targets a named stream."""
    return PublishTask(build=lambda: (stream, b"{}\n"), label=label)


@pytest.mark.asyncio
async def test_worker_batches_queued_records_into_one_sender_call() -> None:
    """Records already queued for one stream ship in a single batch call."""
    calls: list[tuple[str, int]] = []

    async def _sender(stream_name: str, records: list[bytes]) -> int:
        calls.append((stream_name, len(records)))
        return 0

    # Enqueue before start so the worker sees a full queue and drains it greedily.
    queue = _queue(maxsize=100, num_workers=1, batch_sender=_sender)
    for _ in range(20):
        queue.submit_droppable(_task("request_body"))
    await queue.start()
    await queue.stop(drain_timeout=2.0)

    # All 20 shipped in far fewer calls than 20: greedy drain-and-group.
    assert sum(n for _, n in calls) == 20
    assert len(calls) <= 3
    assert all(stream == "request_body" for stream, _ in calls)
    assert queue.published_total == 20


@pytest.mark.asyncio
async def test_worker_groups_mixed_streams_into_per_stream_batches() -> None:
    """A mixed batch is split into one sender call per distinct stream."""
    calls: dict[str, int] = {}

    async def _sender(stream_name: str, records: list[bytes]) -> int:
        calls[stream_name] = calls.get(stream_name, 0) + len(records)
        return 0

    queue = _queue(maxsize=100, num_workers=1, batch_sender=_sender)
    for _ in range(5):
        queue.submit_droppable(_task("request_body"))
    for _ in range(3):
        queue.submit_droppable(_task("response_body"))
    await queue.start()
    await queue.stop(drain_timeout=2.0)

    assert calls == {"request_body": 5, "response_body": 3}


@pytest.mark.asyncio
async def test_max_batch_caps_records_per_sender_call() -> None:
    """``max_batch`` bounds how many queued records one call drains."""
    calls: list[int] = []

    async def _sender(stream_name: str, records: list[bytes]) -> int:
        calls.append(len(records))
        return 0

    queue = _queue(maxsize=100, num_workers=1, batch_sender=_sender, max_batch=4)
    for _ in range(10):
        queue.submit_droppable(_task("request_body"))
    await queue.start()
    await queue.stop(drain_timeout=2.0)

    assert sum(calls) == 10
    assert max(calls) <= 4  # no single batch exceeds max_batch


@pytest.mark.asyncio
async def test_sender_partial_failures_count_toward_failed_total() -> None:
    """A sender reporting failures increments failed_total, not published."""

    async def _sender(stream_name: str, records: list[bytes]) -> int:
        return 2  # 2 of each batch failed

    queue = _queue(maxsize=100, num_workers=1, batch_sender=_sender, max_batch=5)
    for _ in range(5):
        queue.submit_droppable(_task("request_body"))
    await queue.start()
    await queue.stop(drain_timeout=2.0)

    assert queue.failed_total == 2
    assert queue.published_total == 3


@pytest.mark.asyncio
async def test_stop_with_queue_full_cancels_workers_without_raising(caplog) -> None:
    """Shutdown under back-pressure must not let QueueFull escape stop().

    Sentinel ``put_nowait(None)`` on a saturated queue would raise QueueFull
    and skip the rest of shutdown. Workers block on the slow sender so the
    queue stays full through drain_timeout, forcing the failure mode; stop()
    must cancel workers and return cleanly.
    """
    sleeping = asyncio.Event()

    async def _slow_sender(stream_name: str, records: list[bytes]) -> int:
        sleeping.set()
        await asyncio.sleep(60)  # well past drain_timeout
        return 0

    # max_batch=1 so the worker takes one item and blocks in the slow
    # sender, leaving the rest of the queue full while stop() runs.
    queue = _queue(
        maxsize=3,
        body_capacity=3,
        num_workers=1,
        batch_sender=_slow_sender,
        max_batch=1,
    )
    await queue.start()

    # Worker pulls the first item and blocks; the queue then fills so the
    # sentinel ``put`` has nowhere to land within drain_timeout.
    queue.submit_droppable(_noop_task("trigger"))
    await asyncio.wait_for(sleeping.wait(), timeout=1.0)
    queue.submit_droppable(_noop_task("filler-a"))
    queue.submit_droppable(_noop_task("filler-b"))
    queue.submit_droppable(_noop_task("filler-c"))
    assert queue.qsize() == 3

    # stop() must NOT raise (regression: QueueFull escaping from put_nowait).
    with caplog.at_level("WARNING"):
        await queue.stop(drain_timeout=0.1)

    # Workers cancelled, registry cleared; warning signals the slow path.
    assert queue._workers == []  # noqa: SLF001 — direct inspection of cleared state
    assert any(
        "did not drain" in record.message for record in caplog.records
    ), "expected the slow-shutdown warning to be emitted"


@pytest.mark.asyncio
async def test_stop_counts_unflushed_records_on_cancelled_total(caplog) -> None:
    """A timed-out drain records the lost count on ``cancelled_total``, which.

    must equal stop()'s return and stay distinct from ``dropped_total``
    (submit pressure) and ``delivery_failed_total`` (Firehose), both 0 here.
    """
    sleeping = asyncio.Event()

    async def _slow_sender(stream_name: str, records: list[bytes]) -> int:
        sleeping.set()
        await asyncio.sleep(60)
        return 0

    queue = _queue(
        maxsize=10,
        body_capacity=10,
        num_workers=1,
        batch_sender=_slow_sender,
        max_batch=1,
    )
    await queue.start()

    queue.submit_droppable(_noop_task("trigger"))
    await asyncio.wait_for(sleeping.wait(), timeout=1.0)
    for n in range(4):
        queue.submit_droppable(_noop_task(f"filler-{n}"))

    assert queue.cancelled_total == 0  # nothing lost yet

    cancelled = await queue.stop(drain_timeout=0.1)

    assert cancelled > 0
    assert queue.cancelled_total == cancelled
    # Shutdown loss is a separate bucket from drops and delivery failures.
    assert queue.dropped_total == 0
    assert queue.delivery_failed_total == 0


@pytest.mark.asyncio
async def test_saturation_drops_bodies_keeps_metadata_and_drains_sentinels() -> None:
    """Flood PAST body capacity; the tiered queue's four-part contract holds:.

    (a) bodies drop once the queue hits ``body_capacity``;
    (b) metadata still enqueues via the reserved headroom, never waiting;
    (c) ``dropped_total`` accounts for every rejected body;
    (d) shutdown sentinels survive the flood — every worker consumes its
        sentinel and the drain completes cleanly (returns 0, nothing lost).
    """
    published: dict[str, int] = {}

    async def _counting_sender(stream_name: str, records: list[bytes]) -> int:
        published[stream_name] = published.get(stream_name, 0) + len(records)
        return 0

    # 100/90 mirrors the prod 10000/9000 ratio at a test-fast scale.
    queue = _queue(
        maxsize=100,
        body_capacity=90,
        num_workers=4,
        batch_sender=_counting_sender,
    )

    # Saturate before starting workers so the drop policy is deterministic
    # (no worker draining underneath us).
    accepted = [queue.submit_droppable(_task("body")) for _ in range(200)]
    assert accepted.count(True) == 90  # (a) bodies capped at body_capacity
    assert accepted.count(False) == 110
    assert queue.dropped_total == 110  # (c) every rejected body counted
    assert queue.qsize() == 90

    # (b) metadata uses the 10-slot headroom and must enqueue immediately.
    for _ in range(10):
        await asyncio.wait_for(
            queue.submit_blocking(_task("headers", label="header")),
            timeout=0.5,
        )
    assert queue.qsize() == 100  # full, but metadata all landed

    # (d) Drain: a lost sentinel would hang a worker (cancelled > 0); a
    # clean drain proves sentinels are immune to the drop policy.
    await queue.start()
    cancelled = await queue.stop(drain_timeout=5.0)

    assert cancelled == 0
    assert queue.cancelled_total == 0
    assert queue._workers == []  # noqa: SLF001 — all workers exited on their sentinel
    # Every accepted record flushed: 90 bodies + 10 metadata, none lost.
    assert published == {"body": 90, "headers": 10}
    assert queue.published_total == 100


# ---------------------------------------------------------------------------
# Byte bound: queued payload bytes are capped regardless of record count
# ---------------------------------------------------------------------------


def _sized_task(size: int, label: str = "body") -> PublishTask:
    return PublishTask(build=lambda: ("body", b"{}\n"), label=label, size_bytes=size)


@pytest.mark.asyncio
async def test_max_bytes_caps_queued_payload_regardless_of_record_count() -> None:
    """The memory bound: bodies drop once the BYTE budget is hit, regardless.

    of record count (the count cap alone could accumulate GiBs of chunks).
    """
    queue = _queue(
        maxsize=1_000,
        body_capacity=1_000,
        num_workers=0,
        max_bytes=10_000,
    )

    accepted = [queue.submit_droppable(_sized_task(500)) for _ in range(100)]

    # Byte budget's worth accepted (20 × 500 = 10 000), though the record
    # count (20) is nowhere near body_capacity.
    assert accepted.count(True) == 20
    assert queue.queued_bytes == 10_000
    assert queue.qsize() == 20
    assert queue.dropped_total == 80
    # Budget can never be exceeded by a further submit.
    assert queue.submit_droppable(_sized_task(1)) is False
    assert queue.queued_bytes <= 10_000


@pytest.mark.asyncio
async def test_byte_budget_is_released_after_flush_not_at_dequeue() -> None:
    """Bytes stay charged while the task is queued OR in an in-flight batch.

    (a wedged sender still holds the chunk); a completed flush releases them.
    """
    release = asyncio.Event()
    entered = asyncio.Event()

    async def _gated_sender(stream_name: str, records: list[bytes]) -> int:
        entered.set()
        await release.wait()
        return 0

    queue = _queue(
        maxsize=100,
        body_capacity=100,
        num_workers=1,
        batch_sender=_gated_sender,
        max_bytes=1_000,
    )
    assert queue.submit_droppable(_sized_task(800)) is True
    await queue.start()
    await asyncio.wait_for(entered.wait(), timeout=1.0)

    # In-flight batch (qsize 0) but bytes still charged, so a new 800-byte
    # body must be REJECTED while the sender is slow.
    assert queue.qsize() == 0
    assert queue.queued_bytes == 800
    assert queue.submit_droppable(_sized_task(800)) is False

    # Once the flush completes, the budget frees up.
    release.set()
    for _ in range(200):
        if queue.queued_bytes == 0:
            break
        await asyncio.sleep(0.01)
    assert queue.queued_bytes == 0
    assert queue.submit_droppable(_sized_task(800)) is True

    await queue.stop(drain_timeout=2.0)


# ---------------------------------------------------------------------------
# submitted_total + reconciliation: drain loss is quantifiable, in-flight
# batches included
# ---------------------------------------------------------------------------


def _reconciled(queue: BoundedPublishQueue) -> bool:
    return queue.submitted_total == (
        queue.published_total
        + queue.dropped_total
        + queue.build_failed_total
        + queue.delivery_failed_total
        + queue.skipped_unconfigured_total
        + queue.cancelled_total
    )


@pytest.mark.asyncio
async def test_wedged_sender_drain_counts_in_flight_batch_as_cancelled() -> None:
    """10 records pulled into one in-flight batch with a wedged sender: a.

    qsize()-based loss count reports 0 while 10 vanish. The in-flight batch
    must count as cancelled and reconciliation must hold.
    """
    sleeping = asyncio.Event()

    async def _wedged_sender(stream_name: str, records: list[bytes]) -> int:
        sleeping.set()
        await asyncio.sleep(60)
        return 0

    # Large max_batch: the worker greedily pulls all 10 into one batch,
    # leaving qsize()==0 — the blind spot of the old count.
    queue = _queue(
        maxsize=50,
        body_capacity=50,
        num_workers=1,
        batch_sender=_wedged_sender,
        max_batch=500,
    )
    for _ in range(10):
        assert queue.submit_droppable(_noop_task()) is True
    await queue.start()
    await asyncio.wait_for(sleeping.wait(), timeout=1.0)
    assert queue.qsize() == 0  # everything is in the in-flight batch

    cancelled = await queue.stop(drain_timeout=0.1)

    # All 10 in-flight records reported and counted as loss.
    assert cancelled == 10
    assert queue.cancelled_total == 10
    assert queue.published_total == 0
    assert queue.submitted_total == 10
    assert _reconciled(queue)


@pytest.mark.asyncio
async def test_reconciliation_holds_across_publish_drop_skip_and_fail() -> None:
    """Reconciliation (submitted == published + dropped + build_failed +.

    delivery_failed + skipped_unconfigured + cancelled) holds across every
    terminal path exercised in one run.
    """

    async def _sender(stream_name: str, records: list[bytes]) -> int:
        # Fail one record per batch to exercise delivery_failed.
        return 1

    queue = _queue(
        maxsize=100,
        body_capacity=90,
        num_workers=1,
        batch_sender=_sender,
    )
    # 3 publishable records (one per batch will "fail" → mixed outcome).
    for _ in range(3):
        queue.submit_droppable(_noop_task())
    # 2 whose stream isn't configured (build → None).
    for _ in range(2):
        queue.submit_droppable(PublishTask(build=lambda: None, label="ws_summary"))

    # 1 whose build raises.
    def _boom() -> None:
        raise ValueError("bad record")

    queue.submit_droppable(PublishTask(build=_boom, label="broken"))

    await queue.start()
    await queue.stop(drain_timeout=2.0)

    assert queue.submitted_total == 6
    assert queue.skipped_unconfigured_total == 2
    assert queue.build_failed_total == 1
    assert queue.published_total + queue.delivery_failed_total == 3
    assert _reconciled(queue)


@pytest.mark.asyncio
async def test_droppable_rejects_count_toward_submitted_total() -> None:
    """Drops are submit attempts: the invariant needs them on both sides."""
    queue = _queue(maxsize=10, body_capacity=2, num_workers=0)
    for _ in range(5):
        queue.submit_droppable(_noop_task())
    assert queue.submitted_total == 5
    assert queue.dropped_total == 3
    assert queue.qsize() == 2


@pytest.mark.asyncio
async def test_build_returning_none_counts_skipped_unconfigured() -> None:
    """An unconfigured stream (build()→None) must be a counted skip, not a.

    silent one, or it breaks the reconciliation invariant.
    """
    queue = _queue(maxsize=10, num_workers=1)
    for _ in range(3):
        queue.submit_droppable(PublishTask(build=lambda: None, label="ws_summary"))
    await queue.start()
    cancelled = await queue.stop(drain_timeout=2.0)

    assert cancelled == 0
    assert queue.skipped_unconfigured_total == 3
    assert queue.published_total == 0
    assert _reconciled(queue)


# ---------------------------------------------------------------------------
# submit_blocking timeout + sentinel accounting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_blocking_timeout_counts_one_drop() -> None:
    """A bounded blocking submit that times out is observable loss."""
    queue = _queue(maxsize=1, num_workers=0)
    assert await queue.submit_blocking(_noop_task("first")) is True

    accepted = await queue.submit_blocking(_noop_task("second"), timeout=0.05)

    assert accepted is False
    assert queue.dropped_total == 1
    assert queue.sentinel_dropped_total == 0
    assert queue.submitted_total == 2  # both attempts counted
    assert queue.qsize() == 1  # the first record is still queued, untouched


@pytest.mark.asyncio
async def test_sentinel_submit_timeout_counts_sentinel_dropped_not_dropped() -> None:
    """A drop sentinel that cannot land must NOT double-count ``dropped_total``.

    (the lost chunk was already counted there once).
    """
    queue = _queue(maxsize=1, num_workers=0)
    assert await queue.submit_blocking(_noop_task("occupies-queue")) is True

    accepted = await queue.submit_blocking(
        _noop_task("drop_sentinel"), timeout=0.05, sentinel=True
    )

    assert accepted is False
    assert queue.sentinel_dropped_total == 1
    assert queue.dropped_total == 0
    assert queue.submitted_total == 1  # the timed-out sentinel is not a record


@pytest.mark.asyncio
async def test_reconcile_alarms_when_accounted_exceeds_submitted(caplog) -> None:
    """Over-accounting (accounted > submitted) signals a double-count bug and.

    must emit a metric-filterable ERROR from stop(), not silently return 0
    (unlike unaccounted records, which are repaired into cancelled_total).
    """
    queue = _queue(maxsize=10, num_workers=1)
    assert queue.submit_droppable(_noop_task()) is True
    # Double-count defect: dropped bumped for a record that's also published.
    queue._dropped_total += 2  # noqa: SLF001 — fault injection

    await queue.start()
    with caplog.at_level("ERROR"):
        cancelled = await queue.stop(drain_timeout=2.0)

    assert cancelled == 0  # nothing really lost; nothing "repaired"
    mismatch = [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "audit_counter_mismatch"
    ]
    assert mismatch, "expected the audit_counter_mismatch ERROR"
    assert getattr(mismatch[-1], "over_accounted", None) == 2
