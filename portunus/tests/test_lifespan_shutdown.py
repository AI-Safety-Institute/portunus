"""Tests for graceful WebSocket drain on lifespan shutdown.

These exercise the drain logic in ``portunus.app.lifespan``: active
relay tasks should be given ``drain_timeout`` seconds to finish on
their own (so an in-flight LLM response can stream to its natural
``response.completed`` boundary) before they're force-cancelled.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, patch

import pytest

import portunus.app as app_module


@pytest.fixture
def reset_active_connections():
    """Clear the module-level active set between tests."""
    app_module._active_ws_connections.clear()
    yield
    app_module._active_ws_connections.clear()


async def _run_lifespan(
    drain_timeout: float,
    force_close_timeout: float = 0.5,
    stop_log_queue=None,
) -> AsyncMock:
    """Run the lifespan shutdown phase with patched side-effects.

    Enters the lifespan context manager, then exits it immediately so
    only the shutdown code runs. Redis, log queue, and start/stop are
    stubbed out so the test stays purely focused on WS drain.
    Returns the patched ``state_service`` so callers can assert on it.
    """
    stop_mock = AsyncMock(side_effect=stop_log_queue) if stop_log_queue else AsyncMock()
    with (
        patch.object(app_module, "start_log_queue", new=AsyncMock()),
        patch.object(app_module, "stop_log_queue", new=stop_mock),
        patch.object(app_module, "state_service") as mock_state,
        patch.object(app_module.config.relay, "drain_timeout", drain_timeout),
        patch.object(
            app_module.config.relay, "force_close_timeout", force_close_timeout
        ),
    ):
        mock_state.close_redis_client = AsyncMock()
        async with app_module.lifespan(app_module.portunus):
            pass
    return mock_state


@pytest.mark.asyncio
async def test_fast_tasks_finish_before_cancellation(reset_active_connections):
    """Tasks that finish naturally during drain are not cancelled.

    A task that completes in well under ``drain_timeout`` should be
    marked done via asyncio.wait; the lifespan must not call cancel()
    on it. This is the happy path — an in-flight LLM response finishes
    streaming and the task exits on its own.
    """
    cancelled = False

    async def quick_task() -> None:
        await asyncio.sleep(0.05)

    task = asyncio.create_task(quick_task())
    original_cancel = task.cancel

    def track_cancel(*args, **kwargs):
        nonlocal cancelled
        cancelled = True
        return original_cancel(*args, **kwargs)

    task.cancel = track_cancel  # type: ignore[method-assign]
    app_module._active_ws_connections.add(task)

    await _run_lifespan(drain_timeout=2)

    assert task.done()
    assert not cancelled, "Fast-finishing task should not be force-cancelled"


@pytest.mark.asyncio
async def test_stuck_tasks_are_force_cancelled(reset_active_connections):
    """Tasks still holding an open connection after drain_timeout get cancelled.

    We use a very short drain_timeout so the test runs fast; in prod
    the default (25s) is long enough to cover typical responses.
    """

    async def stuck_task() -> None:
        # Sleep far longer than drain_timeout — simulates a WS that
        # would otherwise stay open past the ECS stop_timeout.
        await asyncio.sleep(60)

    task = asyncio.create_task(stuck_task())
    app_module._active_ws_connections.add(task)

    await _run_lifespan(drain_timeout=0.1)

    assert task.cancelled() or task.done()


@pytest.mark.asyncio
async def test_mixed_fast_and_slow_tasks(reset_active_connections):
    """Fast tasks exit cleanly; only the stuck set is force-cancelled."""
    fast_cancelled = False
    slow_cancelled = False

    async def fast() -> None:
        await asyncio.sleep(0.05)

    async def slow() -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            raise

    fast_task = asyncio.create_task(fast())
    slow_task = asyncio.create_task(slow())

    orig_fast_cancel = fast_task.cancel
    orig_slow_cancel = slow_task.cancel

    def fc(*a, **k):
        nonlocal fast_cancelled
        fast_cancelled = True
        return orig_fast_cancel(*a, **k)

    def sc(*a, **k):
        nonlocal slow_cancelled
        slow_cancelled = True
        return orig_slow_cancel(*a, **k)

    fast_task.cancel = fc  # type: ignore[method-assign]
    slow_task.cancel = sc  # type: ignore[method-assign]

    app_module._active_ws_connections.add(fast_task)
    app_module._active_ws_connections.add(slow_task)

    await _run_lifespan(drain_timeout=0.3)

    assert fast_task.done()
    assert not fast_cancelled, "Fast task should not be force-cancelled"
    assert slow_cancelled, "Stuck task must be force-cancelled after timeout"


@pytest.mark.asyncio
async def test_no_active_connections_skips_drain(reset_active_connections):
    """With no active WS, lifespan shutdown is a no-op for the drain phase."""
    # Just verify it runs without error when the active set is empty.
    await _run_lifespan(drain_timeout=5)
    assert len(app_module._active_ws_connections) == 0


@pytest.mark.asyncio
async def test_log_queue_stopped_after_ws_drain(reset_active_connections):
    """Log queue stop is called AFTER WS drain completes.

    Order matters for downstream log-aggregation integrity: the summary
    record is written by the handler's cleanup path as the relay task
    exits, and the log queue must still be running to publish that
    record.

    To make this check meaningful the task performs an explicit
    "summary publish" step AFTER being cancelled by Phase 2 — if the
    drain returned too early (before the cancelled task's cleanup ran),
    the summary would land after stop_log_queue.
    """
    order: list[str] = []

    async def stuck_task_that_publishes_summary_on_cancel() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # Simulate the handler's shielded summary publish that
            # happens after _relay returns. Must complete before
            # stop_log_queue is called.
            await asyncio.sleep(0.05)
            order.append("summary_published")
            raise

    async def log_stop() -> None:
        order.append("log_queue_stopped")

    task = asyncio.create_task(stuck_task_that_publishes_summary_on_cancel())
    app_module._active_ws_connections.add(task)

    with (
        patch.object(app_module, "start_log_queue", new=AsyncMock()),
        patch.object(app_module, "stop_log_queue", side_effect=log_stop),
        patch.object(app_module, "state_service") as mock_state,
        patch.object(app_module.config.relay, "drain_timeout", 0.1),
    ):
        mock_state.close_redis_client = AsyncMock()
        async with app_module.lifespan(app_module.portunus):
            pass

    assert order == [
        "summary_published",
        "log_queue_stopped",
    ], f"expected summary to flush before log queue stops, got {order}"


@pytest.mark.asyncio
async def test_log_queue_always_stops_even_if_drain_phase_raises(
    reset_active_connections,
):
    """The lifespan's try/finally guarantees log queue drain on failure.

    If Phase 1 ``asyncio.wait`` itself is cancelled (e.g. a second
    SIGTERM causes uvicorn to cancel the lifespan), we still want
    anything already in the log queue to reach Kinesis.
    """
    log_stopped = False

    async def stop() -> None:
        nonlocal log_stopped
        log_stopped = True

    async def hanging_task() -> None:
        await asyncio.Event().wait()

    task = asyncio.create_task(hanging_task())
    app_module._active_ws_connections.add(task)

    async def run_lifespan() -> None:
        with (
            patch.object(app_module, "start_log_queue", new=AsyncMock()),
            patch.object(app_module, "stop_log_queue", side_effect=stop),
            patch.object(app_module, "state_service") as mock_state,
            patch.object(app_module.config.relay, "drain_timeout", 10),
        ):
            mock_state.close_redis_client = AsyncMock()
            async with app_module.lifespan(app_module.portunus):
                pass

    lifespan_task = asyncio.create_task(run_lifespan())
    await asyncio.sleep(0.05)  # let lifespan enter the drain phase
    lifespan_task.cancel()
    try:
        await lifespan_task
    except asyncio.CancelledError:
        pass

    assert log_stopped, "stop_log_queue must run even when drain is cancelled"
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_stragglers_are_logged_at_warning(reset_active_connections, caplog):
    """Force-cancelled WS connections surface at WARNING level.

    Truncated responses are the exact user-visible symptom we're
    trying to reduce — operators need them to show up in alarms, not
    disappear at INFO. The straggler log includes task names so
    operators can grep by request_id.
    """

    async def stuck() -> None:
        await asyncio.Event().wait()

    task = asyncio.create_task(stuck(), name="ws-relay-test-req-id")
    app_module._active_ws_connections.add(task)

    with caplog.at_level(logging.WARNING, logger="api.access"):
        await _run_lifespan(drain_timeout=0.1)

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    msgs = [r.getMessage() for r in warnings]
    assert any(
        "Force-closing" in m for m in msgs
    ), f"expected a WARNING about force-closing stragglers, got {msgs}"
    assert any(
        "ws-relay-test-req-id" in m for m in msgs
    ), f"expected task name in straggler log, got {msgs}"


@pytest.mark.asyncio
async def test_unresponsive_cancellation_logs_error(reset_active_connections, caplog):
    """Tasks that ignore cancellation past force_close_timeout log at ERROR.

    Pins the loudest operator signal — if a relay task swallows its
    cancel and won't exit, we want a clear error with the task name so
    it's debuggable from logs alone.
    """

    async def ignores_cancel() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # Simulate a task whose cleanup hangs longer than force_close_timeout.
            await asyncio.sleep(2)

    task = asyncio.create_task(ignores_cancel(), name="ws-relay-stuck-cleanup")
    app_module._active_ws_connections.add(task)

    with caplog.at_level(logging.ERROR, logger="api.access"):
        await _run_lifespan(drain_timeout=0.05, force_close_timeout=0.1)

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    msgs = [r.getMessage() for r in errors]
    assert any(
        "did not respond to cancellation" in m for m in msgs
    ), f"expected an ERROR about unresponsive cancellation, got {msgs}"
    assert any(
        "ws-relay-stuck-cleanup" in m for m in msgs
    ), f"expected task name in error log, got {msgs}"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_drain_timeout_zero_is_immediate_cancel(reset_active_connections):
    """drain_timeout=0 skips Phase 1 and force-cancels immediately.

    A deployment that wants to disable graceful drain (e.g. for tests)
    should be able to set WS_DRAIN_TIMEOUT=0 without breaking.
    """

    async def stuck() -> None:
        await asyncio.Event().wait()

    task = asyncio.create_task(stuck(), name="ws-relay-zero-timeout")
    app_module._active_ws_connections.add(task)

    await _run_lifespan(drain_timeout=0, force_close_timeout=0.5)

    assert task.cancelled() or task.done()


@pytest.mark.asyncio
async def test_redis_closed_even_if_drain_raises(reset_active_connections):
    """close_redis_client must run even if log queue stop raises.

    Regression pin for a previously latent bug where close_redis_client
    sat outside the try/finally chain — a stop_log_queue failure would
    leak Redis connections silently.
    """

    async def boom() -> None:
        raise RuntimeError("simulated log queue failure")

    task = asyncio.create_task(asyncio.sleep(0.01))
    app_module._active_ws_connections.add(task)

    mock_state = await _run_lifespan(
        drain_timeout=0.5,
        stop_log_queue=boom,
    )

    mock_state.close_redis_client.assert_awaited_once()


@pytest.mark.asyncio
async def test_log_queue_stop_timeout_does_not_hang_lifespan(
    reset_active_connections, caplog
):
    """A wedged log queue worker doesn't hang the whole shutdown.

    Without ``log_queue_stop_timeout`` a stuck Kinesis publish would
    block lifespan until ECS SIGKILL.
    """

    async def hang_forever() -> None:
        await asyncio.Event().wait()

    with (
        patch.object(app_module, "start_log_queue", new=AsyncMock()),
        patch.object(
            app_module, "stop_log_queue", new=AsyncMock(side_effect=hang_forever)
        ),
        patch.object(app_module, "state_service") as mock_state,
        patch.object(app_module.config.relay, "drain_timeout", 0.05),
        patch.object(app_module.config.relay, "force_close_timeout", 0.05),
        patch.object(app_module.config.relay, "log_queue_stop_timeout", 1),
        caplog.at_level(logging.ERROR, logger="api.access"),
    ):
        mock_state.close_redis_client = AsyncMock()
        async with app_module.lifespan(app_module.portunus):
            pass

    msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(
        "Log queue did not drain" in m for m in msgs
    ), f"expected timeout error, got {msgs}"
    # Critical: Redis must still close even though the log queue hung.
    mock_state.close_redis_client.assert_awaited_once()
