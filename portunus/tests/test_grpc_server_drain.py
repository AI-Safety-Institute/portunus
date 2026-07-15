"""Tests for ``stop_grpc_server`` drain budgeting and audit-loss signalling.

Two properties are pinned here:

* **Single shared grace budget** — ``server.stop`` and ``publish_queue.stop``
  run sequentially, so passing each the *full* ``grace_seconds`` meant a
  worst-case 2×grace drain (a wedged sink behind an active stream). That
  overruns the ECS ``stopTimeout`` and risks a SIGKILL the moment an operator
  raises grace. The drain must share one deadline so the total is ≤ grace.
* **Audit loss is alarmable, not silent** — when the queue cancels accepted
  records on a timed-out drain the process still exits 0. That must surface as
  an ERROR with a stable event key (for a CloudWatch metric filter) plus the
  queue's ``cancelled_total`` counter, not a lone WARNING swallowed by the
  clean exit.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import pytest

from portunus.grpc.server import GrpcRuntime, stop_grpc_server
from portunus.services.publish_queue import BoundedPublishQueue, PublishTask


class _FakeServer:
    """grpc.aio.Server stand-in whose ``stop`` consumes a fixed wall-clock slice.

    Simulates an active ext_proc/WS stream that keeps ``server.stop``
    busy for ``stop_duration`` seconds (Envoy closes those streams, not
    us), so the drain-budget arithmetic is exercised against real time.
    """

    def __init__(self, *, stop_duration: float) -> None:
        self._stop_duration = stop_duration
        self.grace_seen: Optional[int] = None

    async def stop(self, grace: int) -> None:
        self.grace_seen = grace
        await asyncio.sleep(self._stop_duration)


class _RecordingQueue:
    """publish_queue stand-in that records the drain budget it was handed."""

    def __init__(self, *, cancelled: int = 0) -> None:
        self._cancelled = cancelled
        self.drain_timeout_seen: Optional[float] = None
        self.submitted_total = 0
        self.published_total = 0
        self.dropped_total = 0
        self.delivery_failed_total = 0
        self.build_failed_total = 0
        self.skipped_unconfigured_total = 0
        self.cancelled_total = 0

    async def stop(self, *, drain_timeout: float) -> int:
        self.drain_timeout_seen = drain_timeout
        self.cancelled_total = self._cancelled
        return self._cancelled


class _FakeHealth:
    async def set(self, service: str, status: object) -> None:  # noqa: A003
        return None


class _FakeProcServicer:
    active_stream_count = 0


class _FakeStateService:
    async def close(self) -> None:
        return None


class _FakePublishService:
    state_service = _FakeStateService()


def _runtime(*, server: object, queue: object) -> GrpcRuntime:
    return GrpcRuntime(
        server=server,  # type: ignore[arg-type]
        proc_servicer=_FakeProcServicer(),  # type: ignore[arg-type]
        publish_queue=queue,  # type: ignore[arg-type]
        publish_service=_FakePublishService(),  # type: ignore[arg-type]
        health_servicer=_FakeHealth(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_drain_gives_queue_only_the_remaining_grace_not_a_second_full_grace():
    """The queue's drain budget is grace MINUS what server.stop already spent.

    Handing the queue ``float(grace_seconds)`` outright stacks a second
    full grace window on top of ``server.stop``; the budget must derive
    from a single shared deadline.
    """
    grace = 1
    reserve = 0.2
    server_stop = 0.3
    server = _FakeServer(stop_duration=server_stop)
    queue = _RecordingQueue(cancelled=0)

    await stop_grpc_server(
        _runtime(server=server, queue=queue),
        grace_seconds=grace,
        flush_reserve_seconds=reserve,
    )

    # server.stop gets the grace MINUS the flush reserve (it self-bounds,
    # returning early if streams end).
    assert server.grace_seen == pytest.approx(grace - reserve)
    # The queue got the REMAINING budget, not a second full grace.
    assert queue.drain_timeout_seen is not None
    assert queue.drain_timeout_seen < grace
    # server.stop slept ~server_stop, so the remainder is bounded by it.
    # (sleep is a floor, so the true remainder is only ever smaller.)
    assert queue.drain_timeout_seen + server_stop <= grace + 0.2
    assert queue.drain_timeout_seen >= 0.0


@pytest.mark.asyncio
async def test_drain_total_time_bounded_by_single_grace_with_wedged_sink():
    """Active stream + wedged Firehose must not drain for ~2×grace.

    ``server.stop`` consumes most of the grace (active stream); the real
    queue is wedged behind a slow sender with records still buffered. The
    total must stay bounded by one grace window, with the lost records
    counted on ``cancelled_total``.
    """
    grace = 1
    sleeping = asyncio.Event()

    async def _wedged_sender(stream_name: str, records: list[bytes]) -> int:
        sleeping.set()
        await asyncio.sleep(60)  # never returns within the drain window
        return 0

    # max_batch=1 so the single worker pulls ONE record and blocks in the
    # sender, leaving the rest buffered (a fat batch would empty the queue
    # into the wedged sender and there'd be nothing left to "cancel").
    queue = BoundedPublishQueue(
        maxsize=50,
        body_capacity=50,
        num_workers=1,
        batch_sender=_wedged_sender,
        max_batch=1,
    )
    await queue.start()
    for _ in range(10):
        queue.submit_droppable(PublishTask(build=lambda: ("body", b"{}\n"), label="b"))
    await asyncio.wait_for(sleeping.wait(), timeout=1.0)

    # server.stop eats ~85% of the grace; the queue then gets only the
    # ~15% remainder rather than a second full second.
    server = _FakeServer(stop_duration=0.85 * grace)

    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await stop_grpc_server(
        _runtime(server=server, queue=queue),
        grace_seconds=grace,
        flush_reserve_seconds=0.15 * grace,
    )
    elapsed = loop.time() - t0

    # ~1.0s with the shared deadline; a 2×grace drain would be ~1.85s here.
    assert elapsed <= grace + 0.4, f"drain overran one grace window: {elapsed:.2f}s"
    # Records that never flushed are counted, not silently discarded.
    assert queue.cancelled_total > 0


@pytest.mark.asyncio
async def test_drain_logs_error_event_when_audit_records_cancelled(caplog):
    """Cancelled audit on drain emits an ERROR with a metric-filterable event.

    A clean ``exit 0`` would otherwise hide the loss; an operator needs a
    stable key to alarm on.
    """
    server = _FakeServer(stop_duration=0.0)
    queue = _RecordingQueue(cancelled=7)

    with caplog.at_level("ERROR", logger="api.grpc"):
        await stop_grpc_server(_runtime(server=server, queue=queue), grace_seconds=2)

    errors = [r for r in caplog.records if r.levelno >= 40]
    assert errors, "expected an ERROR-level record when audit was lost on drain"
    rec = errors[-1]
    # Structured fields a CloudWatch metric filter can match on.
    assert getattr(rec, "event", None) == "audit_records_lost_on_drain"
    assert getattr(rec, "lost_audit_records", None) == 7


@pytest.mark.asyncio
async def test_drain_does_not_log_error_on_clean_drain(caplog):
    """A clean drain (nothing cancelled) emits no audit-loss ERROR."""
    server = _FakeServer(stop_duration=0.0)
    queue = _RecordingQueue(cancelled=0)

    with caplog.at_level("ERROR", logger="api.grpc"):
        await stop_grpc_server(_runtime(server=server, queue=queue), grace_seconds=2)

    assert not [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "audit_records_lost_on_drain"
    ]


class _EnvoyHeldStreamServer:
    """``server.stop`` consumes its ENTIRE grace before returning.

    Models the routine busy-stop case: any active ext_proc stream is held
    open by Envoy for its own (longer) drain — grpc.aio can't end it early,
    so ``stop`` only returns at grace expiry.
    """

    def __init__(self) -> None:
        self.grace_seen: Optional[float] = None

    async def stop(self, grace: float) -> None:
        self.grace_seen = grace
        await asyncio.sleep(grace)


@pytest.mark.asyncio
async def test_flush_reserve_leaves_nonzero_queue_budget_when_streams_held_open():
    """An active stream at stop must NOT starve the audit flush to 0 seconds.

    With Envoy holding the stream open, ``server.stop`` uses everything it
    is given. The flush reserve caps what the server drain may consume, so
    the queue always receives ~reserve seconds — a ``drain_timeout=0.0``
    would cancel every buffered record on every busy deploy with a
    perfectly healthy sink.
    """
    grace = 1
    reserve = 0.4
    server = _EnvoyHeldStreamServer()
    queue = _RecordingQueue(cancelled=0)

    await stop_grpc_server(
        _runtime(server=server, queue=queue),
        grace_seconds=grace,
        flush_reserve_seconds=reserve,
    )

    # The server drain was budget-capped at grace - reserve...
    assert server.grace_seen == pytest.approx(grace - reserve)
    # ...and the queue kept a real, non-zero flush window (~the reserve).
    assert queue.drain_timeout_seen is not None
    assert queue.drain_timeout_seen > 0.0
    assert queue.drain_timeout_seen >= reserve * 0.5


@pytest.mark.asyncio
async def test_flush_reserve_larger_than_grace_is_clamped():
    """A reserve bigger than the whole grace must not go negative — the.

    server drain gets 0 and the queue gets (at most) the full grace.
    """
    server = _EnvoyHeldStreamServer()
    queue = _RecordingQueue(cancelled=0)

    await stop_grpc_server(
        _runtime(server=server, queue=queue),
        grace_seconds=1,
        flush_reserve_seconds=30.0,
    )

    assert server.grace_seen == pytest.approx(0.0)
    assert queue.drain_timeout_seen is not None
    assert 0.0 < queue.drain_timeout_seen <= 1.0


@pytest.mark.asyncio
async def test_drain_tears_down_kms_executor_within_deadline(monkeypatch):
    """The drain shuts the dedicated KMS executor down (wait=True) off-loop.

    ``server.stop`` has already ended all RPCs, so in the happy path the
    executor is idle and the join returns immediately — but it must happen
    inside the drain deadline so a leftover KMS thread can't outlive the
    grace window.
    """
    calls: list[dict] = []

    def _spy_reset(*, wait: bool = False) -> None:
        calls.append({"wait": wait})

    import portunus.grpc.server as grpc_server_module

    monkeypatch.setattr(grpc_server_module, "reset_signing_runtime", _spy_reset)

    server = _FakeServer(stop_duration=0.0)
    queue = _RecordingQueue(cancelled=0)
    await stop_grpc_server(
        _runtime(server=server, queue=queue),
        grace_seconds=1,
        flush_reserve_seconds=0.2,
    )

    assert calls == [{"wait": True}]


@pytest.mark.asyncio
async def test_hung_kms_teardown_cannot_push_exit_past_the_drain_deadline(
    monkeypatch,
):
    """A wedged KMS.Sign thread makes ``shutdown(wait=True)`` join forever.

    The teardown runs under the REMAINING drain budget; on timeout the
    drain falls back to a non-blocking shutdown (no join) and proceeds —
    a hung KMS can never push process exit past the ECS stopTimeout.
    """
    calls: list[dict] = []

    def _hung_reset(*, wait: bool = False) -> None:
        calls.append({"wait": wait})
        if wait:
            time.sleep(1.2)  # far past the remaining budget

    import portunus.grpc.server as grpc_server_module

    monkeypatch.setattr(grpc_server_module, "reset_signing_runtime", _hung_reset)

    grace = 1

    class _SlowQueue(_RecordingQueue):
        """Consumes most of the deadline so the teardown budget is small."""

        async def stop(self, *, drain_timeout: float) -> int:
            await asyncio.sleep(min(0.8, drain_timeout))
            return await super().stop(drain_timeout=drain_timeout)

    server = _FakeServer(stop_duration=0.0)
    queue = _SlowQueue(cancelled=0)

    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await stop_grpc_server(
        _runtime(server=server, queue=queue),
        grace_seconds=grace,
        flush_reserve_seconds=0.9,
    )
    elapsed = loop.time() - t0

    # The blocking attempt timed out and the non-blocking fallback ran.
    assert calls[0] == {"wait": True}
    assert calls[-1] == {"wait": False}
    # Exit was not held hostage by the hung join (1.2s sleep).
    assert elapsed <= grace + 0.5, f"drain overran the deadline: {elapsed:.2f}s"
