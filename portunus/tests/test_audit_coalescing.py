"""Audit coalescing must preserve delivery, bounds and cancellation accounting."""

import asyncio

import pytest

from portunus.services.publish_queue import BoundedPublishQueue, PublishTask


def record(value):
    return PublishTask(lambda: ("body", value), "body", size_bytes=len(value))


@pytest.mark.asyncio
async def test_coalesces_new_arrivals_and_drains_without_loss():
    first_sent = asyncio.Event()
    calls = []

    async def send(stream, records):
        calls.append(records.copy())
        first_sent.set()
        return 0

    queue = BoundedPublishQueue(
        maxsize=10, num_workers=1, batch_sender=send, coalesce_seconds=0.04
    )
    queue.submit_droppable(record(b"first"))
    await queue.start()
    await asyncio.wait_for(first_sent.wait(), 1)
    queue.submit_droppable(record(b"second"))
    await asyncio.sleep(0.003)
    queue.submit_droppable(record(b"third"))
    assert await queue.stop(drain_timeout=1) == 0
    assert calls == [[b"first"], [b"second", b"third"]]
    assert queue.published_total == queue.submitted_total == 3
    assert queue.queued_bytes == 0


@pytest.mark.asyncio
async def test_waiting_records_stay_bounded_and_cancelled_records_are_accounted():
    first_sent = asyncio.Event()

    async def send(stream, records):
        first_sent.set()
        return 0

    queue = BoundedPublishQueue(
        maxsize=3,
        body_capacity=2,
        max_bytes=4,
        num_workers=1,
        batch_sender=send,
        coalesce_seconds=0.1,
    )
    assert queue.submit_droppable(record(b"aa"))
    await queue.start()
    await asyncio.wait_for(first_sent.wait(), 1)
    assert queue.queued_bytes == 0
    assert queue.submit_droppable(record(b"bb"))
    assert queue.submit_droppable(record(b"cc"))
    assert not queue.submit_droppable(record(b"dd"))
    assert queue.qsize() == 2
    assert queue.queued_bytes == 4
    assert await queue.stop(drain_timeout=0.001) == 2
    assert queue.published_total == 1
    assert queue.dropped_total == 1
    assert queue.cancelled_total == 2
    assert queue.submitted_total == 4


@pytest.mark.asyncio
async def test_full_batches_do_not_wait_for_coalescing():
    first_sending = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def send(stream, records):
        calls.append(records.copy())
        if len(calls) == 1:
            first_sending.set()
            await release.wait()
        return 0

    queue = BoundedPublishQueue(
        maxsize=10,
        num_workers=1,
        max_batch=1,
        batch_sender=send,
        coalesce_seconds=0.1,
    )
    queue.submit_droppable(record(b"first"))
    await queue.start()
    await asyncio.wait_for(first_sending.wait(), 1)
    queue.submit_droppable(record(b"second"))
    queue.submit_droppable(record(b"third"))
    stopping = asyncio.create_task(queue.stop(drain_timeout=0.05))
    await asyncio.sleep(0)
    release.set()
    assert await stopping == 0
    assert calls == [[b"first"], [b"second"], [b"third"]]
    assert queue.published_total == queue.submitted_total == 3


@pytest.mark.parametrize("delay", [-1, float("inf"), float("nan"), 0.101])
def test_invalid_delays_rejected(delay):
    with pytest.raises(ValueError):
        BoundedPublishQueue(
            maxsize=10,
            num_workers=1,
            batch_sender=None,
            coalesce_seconds=delay,
        )


@pytest.mark.asyncio
async def test_slow_destination_keeps_other_worker_progress_and_byte_bound():
    slow_started = asyncio.Event()
    release = asyncio.Event()
    fast_delivered = asyncio.Event()
    delivered = []

    async def send(stream, records):
        if stream == "slow":
            slow_started.set()
            await release.wait()
        delivered.extend((stream, record) for record in records)
        if stream == "fast":
            fast_delivered.set()
        return 0

    queue = BoundedPublishQueue(
        maxsize=4,
        body_capacity=4,
        max_bytes=8,
        num_workers=2,
        max_batch=1,
        batch_sender=send,
        coalesce_seconds=0.005,
    )
    assert queue.submit_droppable(PublishTask(lambda: ("slow", b"slow"), "body", 4))
    await queue.start()
    try:
        await asyncio.wait_for(slow_started.wait(), 1)
        assert queue.submit_droppable(PublishTask(lambda: ("fast", b"fast"), "body", 4))
        assert not queue.submit_droppable(record(b"over"))
        await asyncio.wait_for(fast_delivered.wait(), 1)
        assert queue.queued_bytes == 4
        assert delivered == [("fast", b"fast")]
    finally:
        release.set()
        assert await queue.stop() == 0
    assert delivered == [("fast", b"fast"), ("slow", b"slow")]
    assert queue.published_total == 2
    assert queue.dropped_total == 1
    assert queue.queued_bytes == queue.qsize() == 0
