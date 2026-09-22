"""Stopping publication releases payloads that never reached the sink."""

import asyncio
import gc
import weakref

import pytest

from portunus.services.publish_queue import BoundedPublishQueue, PublishTask


class Payload:
    def __init__(self, value):
        self.value = value

    def build(self):
        return "audit", self.value


@pytest.mark.asyncio
async def test_timed_out_stop_releases_inflight_and_queued_payloads():
    sending = asyncio.Event()
    received = []

    async def send(_stream, records):
        sending.set()
        await asyncio.Event().wait()
        received.extend(records)
        return 0

    queue = BoundedPublishQueue(
        maxsize=4, max_bytes=8, num_workers=1, max_batch=1, batch_sender=send
    )
    first, second = Payload(b"data"), Payload(b"more")
    refs = weakref.ref(first), weakref.ref(second)
    assert queue.submit_droppable(PublishTask(first.build, "audit", 4))
    await queue.start()
    await asyncio.wait_for(sending.wait(), 1)
    assert queue.submit_droppable(PublishTask(second.build, "audit", 4))
    assert not queue.submit_droppable(
        PublishTask(lambda: ("audit", b"drop"), "audit", 4)
    )
    del first, second

    assert await queue.stop(drain_timeout=0.01) == 2
    assert queue.cancelled_total == 2
    assert queue.dropped_total == 1
    assert queue.submitted_total == queue.cancelled_total + queue.dropped_total
    assert queue.queued_bytes == 0
    assert queue.qsize() == 0
    await asyncio.sleep(0)
    gc.collect()
    assert all(ref() is None for ref in refs)
    assert received == []
    assert await queue.stop() == 0


@pytest.mark.asyncio
async def test_stop_without_workers_discards_accepted_payloads_once():
    async def send(_stream, records):
        return 0

    queue = BoundedPublishQueue(maxsize=2, num_workers=1, batch_sender=send)
    assert queue.submit_droppable(PublishTask(lambda: ("audit", b"data"), "audit", 4))
    assert await queue.stop() == 1
    assert queue.queued_bytes == 0
    assert queue.qsize() == 0
    assert await queue.stop() == 0
    assert queue.cancelled_total == queue.submitted_total == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("sentinel", [False, True], ids=["record", "loss-marker"])
@pytest.mark.parametrize("running", [False, True], ids=["before-start", "running"])
async def test_stopping_rejects_blocked_and_late_submissions(running, sentinel):
    sending = asyncio.Event()

    async def send(_stream, _records):
        sending.set()
        await asyncio.Event().wait()
        return 0

    queue = BoundedPublishQueue(
        maxsize=1, max_batch=1, num_workers=1, batch_sender=send
    )

    def make_record(value):
        return PublishTask(lambda: ("audit", value), "audit", len(value))

    if running:
        await queue.start()
        assert await queue.submit_blocking(make_record(b"inflight"))
        await asyncio.wait_for(sending.wait(), 1)
    assert await queue.submit_blocking(make_record(b"queued"))
    pending = asyncio.create_task(
        queue.submit_blocking(make_record(b"pending"), sentinel=sentinel)
    )
    await asyncio.sleep(0)
    assert not pending.done()
    try:
        assert await asyncio.wait_for(queue.stop(drain_timeout=0.01), 1) == (
            2 if running else 1
        )
        assert not await asyncio.wait_for(pending, 0.1)
        assert not await queue.submit_blocking(make_record(b"late"))
        assert not await queue.submit_blocking(
            make_record(b"late marker"), sentinel=True
        )
        assert not queue.submit_droppable(make_record(b"late body"))
        assert queue.qsize() == queue.queued_bytes == 0
        assert queue.sentinel_dropped_total == (2 if sentinel else 1)
        assert queue.dropped_total == (2 if sentinel else 3)
        assert queue.submitted_total == queue.cancelled_total + queue.dropped_total
        assert await queue.stop() == 0
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("sentinel", [False, True], ids=["record", "loss-marker"])
async def test_cancelling_a_blocked_submitter_preserves_the_next_waiter(sentinel):
    accepted = []

    async def send(_stream, records):
        accepted.extend(records)
        return 0

    queue = BoundedPublishQueue(maxsize=1, num_workers=1, batch_sender=send)
    first = PublishTask(lambda: ("audit", b"first"), "audit", 5)
    cancelled = PublishTask(lambda: ("audit", b"cancelled"), "audit", 9)
    last = PublishTask(lambda: ("audit", b"last"), "audit", 4)
    assert await queue.submit_blocking(first)
    abandoned = asyncio.create_task(queue.submit_blocking(cancelled, sentinel=sentinel))
    survivor = asyncio.create_task(queue.submit_blocking(last, timeout=1))
    await asyncio.sleep(0)
    abandoned.cancel()
    with pytest.raises(asyncio.CancelledError):
        await abandoned
    await queue.start()
    assert await survivor
    assert await queue.stop() == 0
    assert accepted == [b"first", b"last"]
    assert queue.published_total == 2
    assert queue.submitted_total == (2 if sentinel else 3)
    assert queue.cancelled_total == (0 if sentinel else 1)
    assert queue.sentinel_dropped_total == (1 if sentinel else 0)
    assert queue.queued_bytes == queue.qsize() == 0
