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
