"""Audit admission remains bounded during destination outages."""

import asyncio

import pytest

from portunus.services.publish_queue import BoundedPublishQueue, PublishTask


async def discard_batch(stream, records):
    return len(records)


@pytest.mark.asyncio
async def test_overloaded_audit_admission_drops_promptly_and_accounts_for_loss():
    queue = BoundedPublishQueue(
        maxsize=1, num_workers=1, batch_sender=discard_batch, drop_on_pressure=True
    )
    record = PublishTask(build=lambda: ("body", b"{}"), label="body")
    assert queue.submit_droppable(record)
    assert not await asyncio.wait_for(queue.submit_blocking(record, timeout=5), 0.1)
    assert not await asyncio.wait_for(
        queue.submit_blocking(record, timeout=5, sentinel=True), 0.1
    )
    assert queue.qsize() == 1
    assert queue.submitted_total == 2
    assert queue.dropped_total == 1
    assert queue.sentinel_dropped_total == 1
