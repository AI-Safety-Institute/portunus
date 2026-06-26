"""Tests for ``BoundedPublishQueue`` tiering between metadata and bodies.

The contract these tests pin: a body flood that drives the queue to
saturation must not stall ``submit_blocking`` (which is on the
header/trailer/ws-summary path). Without the body_capacity reserve,
``submit_blocking`` would wait on a body-saturated queue and add
queue-drain latency directly to the customer request path.
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
    """The headroom reserve lets metadata enqueue without blocking on bodies.

    Bodies fill the queue up to ``body_capacity``. A blocking metadata
    submit should slot in immediately above the reserve, not wait for
    a worker to drain bodies (which is the failure mode we're guarding).
    """
    queue = _queue(
        maxsize=10,
        body_capacity=6,
        num_workers=0,
    )

    for _ in range(6):
        assert queue.submit_droppable(_noop_task("body")) is True

    # Saturated for bodies, but four metadata slots remain. Each
    # submit_blocking must complete without yielding back to the loop
    # for a worker to free space — the queue still has open slots.
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
    """Edge: ``body_capacity=0`` disables body publishing entirely.

    Not a recommended config, but exercises the boundary so an
    accidental ``body_capacity=0`` doesn't deadlock metadata.
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

    # 1 worker, no auto-start: enqueue first, then start so the worker sees
    # a full queue and drains it in one greedy batch.
    queue = _queue(maxsize=100, num_workers=1, batch_sender=_sender)
    for _ in range(20):
        queue.submit_droppable(_task("request_body"))
    await queue.start()
    await queue.stop(drain_timeout=2.0)

    # All 20 same-stream records shipped, and in far fewer calls than 20
    # (ideally one) — proves greedy drain-and-group, not one-call-per-record.
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
    """Shutdown under back-pressure must not let QueueFull escape.

    The pre-fix shape used ``put_nowait(None)`` to inject worker
    sentinels, which raises ``QueueFull`` exactly when audit pressure
    is highest — at shutdown, with a saturated queue. That exception
    would unwind out of ``stop()`` and skip the rest of
    ``stop_grpc_server`` (publish drain, Firehose client close).

    Workers are blocked on ``slow_task`` here so the queue stays full
    for the duration of the test, forcing ``put`` to hit the
    drain_timeout. The fix must then cancel the workers and return
    cleanly.
    """
    sleeping = asyncio.Event()

    async def _slow_sender(stream_name: str, records: list[bytes]) -> int:
        sleeping.set()
        await asyncio.sleep(60)  # well past drain_timeout
        return 0

    # max_batch=1 so the single worker takes one item and blocks in the
    # slow sender, leaving the rest of the queue full while stop() runs.
    queue = _queue(
        maxsize=3,
        body_capacity=3,
        num_workers=1,
        batch_sender=_slow_sender,
        max_batch=1,
    )
    await queue.start()

    # First item: the worker pulls it and blocks in _slow_sender. The queue
    # then fills with more tasks so the sentinel ``put`` has nowhere to land
    # within drain_timeout.
    queue.submit_droppable(_noop_task("trigger"))
    await asyncio.wait_for(sleeping.wait(), timeout=1.0)
    queue.submit_droppable(_noop_task("filler-a"))
    queue.submit_droppable(_noop_task("filler-b"))
    queue.submit_droppable(_noop_task("filler-c"))
    assert queue.qsize() == 3

    # ``stop()`` must NOT raise — the regression mode is QueueFull from
    # put_nowait(sentinel) escaping out of stop().
    with caplog.at_level("WARNING"):
        await queue.stop(drain_timeout=0.1)

    # Workers cancelled, registry cleared. The warning log is the
    # operator's "we hit the slow shutdown path" signal.
    assert queue._workers == []  # noqa: SLF001 — direct inspection of cleared state
    assert any(
        "did not drain" in record.message for record in caplog.records
    ), "expected the slow-shutdown warning to be emitted"


@pytest.mark.asyncio
async def test_stop_counts_unflushed_records_on_cancelled_total(caplog) -> None:
    """A timed-out drain records the lost count on ``cancelled_total``.

    ``cancelled_total`` is the in-process counter ``stop_grpc_server``
    alarms on: a clean ``exit 0`` would otherwise hide audit dropped at
    shutdown. It must match what ``stop()`` returns and stay distinct
    from ``dropped_total`` (submit-time pressure) and
    ``delivery_failed_total`` (Firehose rejections), both of which stay 0
    here — the records were accepted and built fine, just never flushed.
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
    # Shutdown loss is a separate bucket from queue-pressure drops and
    # Firehose delivery failures.
    assert queue.dropped_total == 0
    assert queue.delivery_failed_total == 0


@pytest.mark.asyncio
async def test_saturation_drops_bodies_keeps_metadata_and_drains_sentinels() -> None:
    """Flood PAST body capacity; bodies drop, metadata survives, drain is clean.

    The four-part contract the tiered queue exists to uphold under
    genuine saturation (the load-test "zero drops" runs never crossed
    ``body_capacity``, so this is the path that was unit-only):

    (a) body records drop once the queue hits ``body_capacity``;
    (b) header/metadata records still enqueue (blocking submit uses the
        reserved headroom and never waits on a worker);
    (c) ``dropped_total`` accounts for every rejected body;
    (d) shutdown sentinels are NOT lost among the flood — every worker
        consumes its sentinel and the drain completes cleanly (returns 0,
        nothing cancelled), so no queued record is silently discarded.
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

    # Saturate with bodies BEFORE starting workers so the drop policy is
    # exercised deterministically (no worker draining underneath us).
    accepted = [queue.submit_droppable(_task("body")) for _ in range(200)]
    assert accepted.count(True) == 90  # (a) bodies capped at body_capacity
    assert accepted.count(False) == 110
    assert queue.dropped_total == 110  # (c) every rejected body counted
    assert queue.qsize() == 90

    # (b) metadata uses the 10-slot headroom above body_capacity and must
    # enqueue immediately — never block on a body-saturated queue.
    for _ in range(10):
        await asyncio.wait_for(
            queue.submit_blocking(_task("headers", label="header")),
            timeout=0.5,
        )
    assert queue.qsize() == 100  # full, but metadata all landed

    # (d) Now drain. A sentinel lost among the queued items would hang a
    # worker and force the timeout path (cancelled > 0); a clean drain
    # proves sentinels are immune to the drop policy.
    await queue.start()
    cancelled = await queue.stop(drain_timeout=5.0)

    assert cancelled == 0
    assert queue.cancelled_total == 0
    assert queue._workers == []  # noqa: SLF001 — all workers exited on their sentinel
    # Every accepted record flushed: 90 bodies + 10 metadata, none lost.
    assert published == {"body": 90, "headers": 10}
    assert queue.published_total == 100
