"""Tests for the dependency (Redis) health monitor driving gRPC health.

The detection gap being closed (cutover C4 / review HIGH): a Portunus whose
event loop is alive but whose Redis is down times out every ext_authz
``Check`` → fail-closed deny — while the plain health servicer keeps
answering SERVING, so ``grpc_health_probe`` (ECS) and anything watching gRPC
health never notice a task 403ing 100% of its traffic. The monitor pings the
dependency on an interval and flips the overall ("") status accordingly.

Health-semantics contract (deploy side points probes at this):
``grpc.health.v1.Health`` "" == SERVING iff the listener is up AND the last
dependency probe succeeded; NOT_SERVING during a Redis outage and from drain
start onward.
"""

from __future__ import annotations

import asyncio

import pytest
from grpc_health.v1 import health_pb2

from portunus.config import FirehoseConfig, GrpcConfig
from portunus.grpc.server import (
    _dependency_health_loop,
    start_grpc_server,
    stop_grpc_server,
)

SERVING = health_pb2.HealthCheckResponse.SERVING
NOT_SERVING = health_pb2.HealthCheckResponse.NOT_SERVING


class _RecordingHealthServicer:
    """Captures every status transition the monitor sets."""

    def __init__(self) -> None:
        self.statuses: list[int] = []

    async def set(self, service: str, status: int) -> None:  # noqa: A003
        assert service == ""
        self.statuses.append(status)


class _ToggleDependency:
    """StateService.health_check stand-in with a flip-able result."""

    def __init__(self) -> None:
        self.ok = True
        self.checks = 0

    async def health_check(self) -> bool:
        self.checks += 1
        return self.ok


async def _wait_for(predicate, *, timeout: float = 2.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met within timeout")


@pytest.mark.asyncio
async def test_monitor_flips_not_serving_on_dependency_failure_and_recovers():
    """Redis down → NOT_SERVING; Redis back → SERVING. One transition each,.

    not one set() per probe.
    """
    health = _RecordingHealthServicer()
    dependency = _ToggleDependency()
    task = asyncio.create_task(
        _dependency_health_loop(
            health,  # type: ignore[arg-type]
            dependency,
            interval_seconds=0.01,
            timeout_seconds=0.5,
        )
    )
    try:
        # Healthy: several probe cycles, no status churn.
        await _wait_for(lambda: dependency.checks >= 3)
        assert health.statuses == []

        # Dependency dies → exactly one NOT_SERVING flip.
        dependency.ok = False
        await _wait_for(lambda: NOT_SERVING in health.statuses)
        checks_at_flip = dependency.checks
        await _wait_for(lambda: dependency.checks >= checks_at_flip + 3)
        assert health.statuses == [NOT_SERVING]

        # Dependency recovers → exactly one SERVING flip.
        dependency.ok = True
        await _wait_for(lambda: SERVING in health.statuses)
        assert health.statuses == [NOT_SERVING, SERVING]
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_monitor_treats_probe_exceptions_and_timeouts_as_unhealthy():
    """A hung or raising dependency check must count as DOWN, not be skipped —.

    a wedged Redis client hangs rather than failing fast.
    """
    health = _RecordingHealthServicer()

    class _HangingDependency:
        async def health_check(self) -> bool:
            await asyncio.sleep(60)
            return True

    task = asyncio.create_task(
        _dependency_health_loop(
            health,  # type: ignore[arg-type]
            _HangingDependency(),
            interval_seconds=0.01,
            timeout_seconds=0.05,
        )
    )
    try:
        await _wait_for(lambda: NOT_SERVING in health.statuses)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


class _FakeStateService:
    def __init__(self) -> None:
        self.ok = True

    async def health_check(self) -> bool:
        return self.ok

    async def close(self) -> None:
        return None


class _FakePublishServiceWithState:
    def __init__(self) -> None:
        self.state_service = _FakeStateService()

    async def put_record_batch(self, stream_name: str, records: list[bytes]) -> int:
        return 0


def _configured_firehose() -> FirehoseConfig:
    return FirehoseConfig(
        metadata_stream_name="metadata",
        request_headers_stream_name="req-headers",
        request_body_stream_name="req-body",
        request_trailers_stream_name="req-trailers",
        response_headers_stream_name="resp-headers",
        response_body_stream_name="resp-body",
        response_trailers_stream_name="resp-trailers",
    )


class _FakeAuthService:
    pass


@pytest.mark.asyncio
async def test_server_startup_wires_the_monitor_and_drain_cancels_it():
    """start_grpc_server starts the monitor when a state service is available;.

    stop_grpc_server cancels it BEFORE flipping NOT_SERVING so the monitor
    can never resurrect a draining task's status.
    """
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="a-real-proxy-key-with-length",
        port=50061,
        health_check_interval_seconds=0.05,
        health_check_timeout_seconds=0.5,
    )
    runtime = await start_grpc_server(
        config=config,
        firehose=_configured_firehose(),
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        publish_service=_FakePublishServiceWithState(),  # type: ignore[arg-type]
    )
    assert runtime is not None
    try:
        assert runtime.health_monitor is not None
        assert not runtime.health_monitor.done()
    finally:
        await stop_grpc_server(runtime, grace_seconds=1, flush_reserve_seconds=0.2)

    assert runtime.health_monitor.done()
