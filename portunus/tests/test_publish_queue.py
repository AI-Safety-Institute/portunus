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


def _noop_task(label: str = "body") -> PublishTask:
    async def _coro() -> None:
        return None

    return PublishTask(coro_fn=_coro, label=label)


@pytest.mark.asyncio
async def test_submit_droppable_drops_at_body_capacity_not_maxsize() -> None:
    """Soft cap protects metadata headroom above ``body_capacity``."""
    queue = BoundedPublishQueue(
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
    queue = BoundedPublishQueue(
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
    queue = BoundedPublishQueue(maxsize=100, num_workers=0)
    for _ in range(100):
        queue.submit_droppable(_noop_task())
    assert queue.qsize() == 90
    assert queue.dropped_total == 10


@pytest.mark.asyncio
async def test_body_capacity_above_maxsize_rejected() -> None:
    """Misconfiguration fails loudly at construction, not at the first submit."""
    with pytest.raises(ValueError):
        BoundedPublishQueue(maxsize=10, body_capacity=11, num_workers=0)


@pytest.mark.asyncio
async def test_body_capacity_zero_drops_all_droppables_but_blocks_pass() -> None:
    """Edge: ``body_capacity=0`` disables body publishing entirely.

    Not a recommended config, but exercises the boundary so an
    accidental ``body_capacity=0`` doesn't deadlock metadata.
    """
    queue = BoundedPublishQueue(maxsize=4, body_capacity=0, num_workers=0)

    assert queue.submit_droppable(_noop_task()) is False
    assert queue.dropped_total == 1

    for _ in range(4):
        await asyncio.wait_for(
            queue.submit_blocking(_noop_task("header")),
            timeout=0.05,
        )
    assert queue.qsize() == 4


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

    async def _slow_task() -> None:
        sleeping.set()
        await asyncio.sleep(60)  # well past drain_timeout

    queue = BoundedPublishQueue(maxsize=2, body_capacity=2, num_workers=1)
    await queue.start()

    # One worker pulls _slow_task; the queue then fills with regular tasks
    # so the sentinel ``put`` has nowhere to land within drain_timeout.
    await queue.submit_blocking(PublishTask(coro_fn=_slow_task, label="slow"))
    await asyncio.wait_for(sleeping.wait(), timeout=1.0)
    queue.submit_droppable(_noop_task("filler-a"))
    queue.submit_droppable(_noop_task("filler-b"))
    assert queue.qsize() == 2

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
