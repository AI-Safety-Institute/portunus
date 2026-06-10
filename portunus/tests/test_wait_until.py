import asyncio
from unittest import mock

import pytest

from portunus.util import wait_until


@pytest.mark.asyncio
async def test_wait_until_timeout():
    test_time = 0

    def pop_test_time():
        nonlocal test_time
        test_time = test_time + 1
        return test_time

    # mock.patch of ``time.time`` is the lightest-touch way to fast-forward
    # ``wait_until`` past its timeout without an actual sleep; injecting a
    # clock through every call site would be heavier than the test.
    with mock.patch("time.time", side_effect=pop_test_time):

        def condition():
            return False

        with pytest.raises(TimeoutError):
            await wait_until(condition, timeout=3, interval=0.1)


@pytest.mark.asyncio
async def test_wait_until_condition_exception():
    async def condition():
        raise ValueError("Test exception")

    with pytest.raises(TimeoutError, match="Condition not met within timeout period"):
        await wait_until(condition, timeout=1, interval=0.1)


@pytest.mark.asyncio
async def test_wait_until_cancelled():
    async def condition():
        return False

    task = asyncio.create_task(wait_until(condition, timeout=5, interval=0.1))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_wait_until_with_gather_return_exceptions():
    async def condition_success():
        return True

    async def condition_fail():
        raise ValueError("Test exception")

    # Test with return_exceptions=True - should return exception objects not raise
    results = await asyncio.gather(
        wait_until(condition_success, timeout=1, interval=0.1),
        wait_until(condition_fail, timeout=1, interval=0.1),
        return_exceptions=True,
    )

    # First should succeed (return None)
    assert results[0] is None

    # Second should return the TimeoutError exception object
    assert isinstance(results[1], TimeoutError)
    assert str(results[1]) == "Condition not met within timeout period"
