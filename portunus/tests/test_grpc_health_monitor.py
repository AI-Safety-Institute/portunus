"""Tests for the liveness/readiness split of the gRPC health services.

Driving the OVERALL ``""`` health service from the Redis monitor is a trap:
the ECS container liveness probe (``grpc_health_probe``, service ``""``)
reads the same status, so a *correlated* Redis outage would NOT_SERVING
every task at once → ECS recycles the whole fleet → replacements can't
start (Envoy dependsOn Portunus-HEALTHY needs Redis) → deadlock.

The contract (keep byte-for-byte in sync with proxy/envoy.yaml):

* ``""`` (overall) = **LIVENESS**: SERVING as soon as the listener binds,
  NOT_SERVING only at drain start. The Redis monitor NEVER touches it.
* ``"readiness"`` (named service) = **READINESS**: driven by the Redis
  monitor with a consecutive-failure debounce before NOT_SERVING and
  immediate re-SERVING on the first success. The ALB /healthz reads it —
  a Redis-down task leaves rotation but is never killed.
"""

from __future__ import annotations

import asyncio

import pytest
from grpc_health.v1 import health_pb2

from portunus.config import FirehoseConfig, GrpcConfig
from portunus.grpc.server import (
    LIVENESS_SERVICE_NAME,
    READINESS_SERVICE_NAME,
    _dependency_health_loop,
    start_grpc_server,
    stop_grpc_server,
)

SERVING = health_pb2.HealthCheckResponse.SERVING
NOT_SERVING = health_pb2.HealthCheckResponse.NOT_SERVING


def test_readiness_service_name_matches_the_envoy_contract():
    """The Envoy active check's ``service_name`` must match byte-for-byte."""
    assert READINESS_SERVICE_NAME == "readiness"
    assert LIVENESS_SERVICE_NAME == ""


class _RecordingHealthServicer:
    """Captures every (service, status) transition set on the servicer."""

    def __init__(self) -> None:
        self.transitions: list[tuple[str, int]] = []

    async def set(self, service: str, status: int) -> None:  # noqa: A003
        self.transitions.append((service, status))

    def for_service(self, service: str) -> list[int]:
        return [st for svc, st in self.transitions if svc == service]


class _ToggleDependency:
    """StateService.health_check stand-in with a flip-able result."""

    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.checks = 0

    async def health_check(self) -> bool:
        self.checks += 1
        return self.ok


async def _wait_for(predicate, *, timeout: float = 2.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not met within timeout")


async def _wait_for_async(predicate, *, timeout: float = 2.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not met within timeout")


def _monitor(
    health: _RecordingHealthServicer,
    dependency,
    *,
    failure_threshold: int = 3,
    interval: float = 0.01,
    timeout: float = 0.5,
) -> asyncio.Task:
    return asyncio.create_task(
        _dependency_health_loop(
            health,  # type: ignore[arg-type]
            dependency,
            interval_seconds=interval,
            timeout_seconds=timeout,
            failure_threshold=failure_threshold,
        )
    )


async def _cancel(task: asyncio.Task) -> None:
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_monitor_drives_readiness_only_and_never_touches_liveness():
    """A full Redis outage + recovery must leave ``""`` (liveness) alone.

    Flipping liveness on a correlated Redis outage recycles the fleet and
    deadlocks replacements — the monitor may only move ``readiness``.
    """
    health = _RecordingHealthServicer()
    dependency = _ToggleDependency(ok=True)
    task = _monitor(health, dependency, failure_threshold=2)
    try:
        # Healthy boot: first probe flips readiness SERVING.
        await _wait_for(lambda: SERVING in health.for_service(READINESS_SERVICE_NAME))

        # Outage past the debounce threshold.
        dependency.ok = False
        await _wait_for(
            lambda: NOT_SERVING in health.for_service(READINESS_SERVICE_NAME)
        )

        # Recovery: first success re-SERVES immediately.
        dependency.ok = True
        await _wait_for(
            lambda: health.for_service(READINESS_SERVICE_NAME)[-1] == SERVING
        )

        # LIVENESS ("") was never touched by the monitor — across boot,
        # outage, and recovery.
        assert health.for_service(LIVENESS_SERVICE_NAME) == []
        # And readiness saw exactly one transition per state change.
        assert health.for_service(READINESS_SERVICE_NAME) == [
            SERVING,
            NOT_SERVING,
            SERVING,
        ]
    finally:
        await _cancel(task)


class _ScriptedDependency:
    """Fails on scripted probe indices, succeeds otherwise."""

    def __init__(self, fail_on: set[int]) -> None:
        self.fail_on = fail_on
        self.checks = 0

    async def health_check(self) -> bool:
        self.checks += 1
        return self.checks not in self.fail_on


@pytest.mark.asyncio
async def test_readiness_survives_failures_below_the_debounce_threshold():
    """threshold-1 consecutive failures must NOT pull the task.

    A single >timeout Redis ping is routine; only ``failure_threshold``
    CONSECUTIVE failures flip readiness NOT_SERVING.
    """
    health = _RecordingHealthServicer()
    # Probes: ok, FAIL, FAIL, ok, ok, ok — two consecutive failures with
    # threshold 3 must not flip readiness.
    dependency = _ScriptedDependency(fail_on={2, 3})
    task = _monitor(health, dependency, failure_threshold=3)
    try:
        await _wait_for(lambda: dependency.checks >= 6)
        assert health.for_service(READINESS_SERVICE_NAME) == [SERVING]
    finally:
        await _cancel(task)


@pytest.mark.asyncio
async def test_readiness_flips_at_the_debounce_threshold_and_recovers_fast():
    """Threshold consecutive failures flip readiness; ONE success restores."""
    health = _RecordingHealthServicer()
    dependency = _ScriptedDependency(fail_on={2, 3, 4})
    task = _monitor(health, dependency, failure_threshold=3)
    try:
        await _wait_for(
            lambda: NOT_SERVING in health.for_service(READINESS_SERVICE_NAME)
        )
        # The flip happened on probe #4 (the 3rd consecutive failure).
        assert dependency.checks >= 4
        # Recovery on the very next success — no debounce on the way back.
        await _wait_for(
            lambda: health.for_service(READINESS_SERVICE_NAME)[-1] == SERVING
        )
        assert health.for_service(READINESS_SERVICE_NAME) == [
            SERVING,
            NOT_SERVING,
            SERVING,
        ]
        assert health.for_service(LIVENESS_SERVICE_NAME) == []
    finally:
        await _cancel(task)


@pytest.mark.asyncio
async def test_hung_or_raising_probe_counts_as_a_failure():
    """A wedged Redis client hangs rather than failing fast.

    A probe that exceeds its timeout (or raises) must count toward the
    debounce like any other failure.
    """
    health = _RecordingHealthServicer()

    class _HangingDependency:
        async def health_check(self) -> bool:
            await asyncio.sleep(60)
            return True

    task = _monitor(health, _HangingDependency(), failure_threshold=2, timeout=0.02)
    try:
        await _wait_for(
            lambda: NOT_SERVING in health.for_service(READINESS_SERVICE_NAME)
        )
        assert health.for_service(LIVENESS_SERVICE_NAME) == []
    finally:
        await _cancel(task)


# ---------------------------------------------------------------------------
# start/stop wiring — the e2e shape probes actually see
# ---------------------------------------------------------------------------


class _FakeStateService:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok

    async def health_check(self) -> bool:
        return self.ok

    async def close(self) -> None:
        return None


class _FakePublishServiceWithState:
    def __init__(self, *, redis_ok: bool = True) -> None:
        self.state_service = _FakeStateService(ok=redis_ok)

    async def put_record_batch(self, stream_name: str, records: list[bytes]) -> int:
        return 0


class _FakePublishServiceNoState:
    """No state_service attribute → the monitor is disabled."""

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


def _grpc_config(port: int, **overrides) -> GrpcConfig:
    kwargs: dict = dict(
        enabled=True,
        proxy_api_key="a-real-proxy-key-with-length",
        port=port,
        health_check_interval_seconds=0.02,
        health_check_timeout_seconds=0.5,
        health_check_failure_threshold=2,
    )
    kwargs.update(overrides)
    return GrpcConfig(**kwargs)


async def _status(runtime, service: str) -> int:
    """Read a health status via the servicer's Check (what probes see)."""
    request = health_pb2.HealthCheckRequest(service=service)
    response = await runtime.health_servicer.Check(request, None)
    return response.status


@pytest.mark.asyncio
async def test_liveness_stays_serving_across_redis_outage():
    """The end-to-end shape of the liveness/readiness split.

    Redis dies → readiness NOT_SERVING (task leaves ALB rotation) while
    liveness stays SERVING (ECS never recycles the task); recovery restores
    readiness; the drain flips both.
    """
    publish = _FakePublishServiceWithState(redis_ok=True)
    runtime = await start_grpc_server(
        config=_grpc_config(50062),
        firehose=_configured_firehose(),
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        publish_service=publish,  # type: ignore[arg-type]
    )
    assert runtime is not None
    try:
        # Healthy boot: liveness SERVING immediately, readiness within one
        # probe round-trip.
        assert await _status(runtime, LIVENESS_SERVICE_NAME) == SERVING

        async def _ready() -> bool:
            return await _status(runtime, READINESS_SERVICE_NAME) == SERVING

        await _wait_for_async(_ready)

        # Redis outage: readiness flips (after the debounce), liveness holds.
        publish.state_service.ok = False

        async def _not_ready() -> bool:
            return await _status(runtime, READINESS_SERVICE_NAME) == NOT_SERVING

        await _wait_for_async(_not_ready)
        assert await _status(runtime, LIVENESS_SERVICE_NAME) == SERVING

        # Recovery: readiness returns on the first good probe.
        publish.state_service.ok = True
        await _wait_for_async(_ready)
        assert await _status(runtime, LIVENESS_SERVICE_NAME) == SERVING
    finally:
        await stop_grpc_server(runtime, grace_seconds=1, flush_reserve_seconds=0.2)

    # Drain flips BOTH: intentional shutdown is the one case liveness moves.
    assert await _status(runtime, LIVENESS_SERVICE_NAME) == NOT_SERVING
    assert await _status(runtime, READINESS_SERVICE_NAME) == NOT_SERVING
    assert runtime.health_monitor is not None
    assert runtime.health_monitor.done()


@pytest.mark.asyncio
async def test_monitor_disabled_reports_readiness_serving():
    """No state service (or interval=0) → readiness must report SERVING.

    Otherwise a monitor-disabled deployment (tests, local dev) would fail
    the /healthz-gated probes forever.
    """
    runtime = await start_grpc_server(
        config=_grpc_config(50063),
        firehose=_configured_firehose(),
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        publish_service=_FakePublishServiceNoState(),  # type: ignore[arg-type]
    )
    assert runtime is not None
    try:
        assert runtime.health_monitor is None
        assert await _status(runtime, LIVENESS_SERVICE_NAME) == SERVING
        assert await _status(runtime, READINESS_SERVICE_NAME) == SERVING
    finally:
        await stop_grpc_server(runtime, grace_seconds=1, flush_reserve_seconds=0.2)
