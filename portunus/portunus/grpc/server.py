"""gRPC service assembly, health reporting, and process lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Optional, Protocol

import grpc
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from portunus.config import FirehoseConfig, GrpcConfig, MetricsConfig
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.metrics import (
    ACTIVE_EXT_PROC_STREAMS,
    AUTH_L1_COALESCED,
    AUTH_L1_HIT,
    AUTH_L1_MISS,
    AUTH_L1_STALE_SERVED,
    BUILD_FAILED_RECORDS,
    DELIVERY_FAILED_RECORDS,
    DROPPED_RECORDS,
    EVENT_LOOP_LAG,
    FIREHOSE_PUT_ERRORS,
    FIREHOSE_THROTTLED_RECORDS,
    PUBLISH_QUEUE_BYTES,
    PUBLISH_QUEUE_DEPTH,
    PUBLISHED_RECORDS,
    SENTINEL_DROPPED_RECORDS,
    SKIPPED_UNCONFIGURED_RECORDS,
    SUBMITTED_RECORDS,
    MetricsAggregator,
    configure_metrics,
)
from portunus.services.auth_service import AuthService
from portunus.services.publish_queue import BoundedPublishQueue
from portunus.services.publish_service import PublishService
from portunus.services.signing_service import reset_signing_runtime, sign_request

if sys.platform not in {"win32", "cygwin"} and sys.implementation.name == "cpython":
    from uvloop import run as run_event_loop
else:
    from asyncio import run as run_event_loop

logger = logging.getLogger("api.grpc")

# Envoy may buffer a 32 MiB signed body; the CheckRequest adds headers and
# protobuf framing, so the gRPC receive limit needs headroom.
_MAX_GRPC_MSG_BYTES = 64 * 1024 * 1024

# Minimum proxy-key length. The empty-key guard passes a 1-char placeholder
# that gives no real channel-identity protection — refuse it too.
_MIN_PROXY_KEY_BYTES = 16

# gRPC health-service names — the liveness/readiness split.
#
# ``""`` (default service) is LIVENESS: SERVING once the listener binds,
# NOT_SERVING only at drain start. The ECS container probe (``grpc_health_probe``,
# default service "") reads it, so a Redis outage never recycles a task.
#
# ``"readiness"`` is driven by the Redis monitor (consecutive-failure debounce)
# and read by the ALB /healthz (Envoy gRPC health check, service_name
# "readiness"), so a Redis-down task leaves rotation without being killed. Keep
# this string in sync with proxy/envoy.yaml's grpc_health_check.service_name.
LIVENESS_SERVICE_NAME = ""
READINESS_SERVICE_NAME = "readiness"


class _DependencyHealth(Protocol):
    """The slice of StateService the health monitor needs."""

    async def health_check(self) -> bool: ...


@dataclass
class GrpcRuntime:
    """Aggregates the gRPC server and components needing orderly shutdown."""

    server: grpc.aio.Server
    proc_servicer: PortunusProcessServicer
    publish_queue: BoundedPublishQueue
    publish_service: PublishService
    health_servicer: health.aio.HealthServicer
    # Background Redis-ping task driving the readiness health status — None when
    # the monitor is disabled or no state service is available.
    health_monitor: Optional[asyncio.Task] = field(default=None)
    # Background CloudWatch EMF reporter — None when metrics are disabled.
    metrics_reporter: Optional[asyncio.Task] = field(default=None)
    # Background event-loop lag probe — None when metrics or the probe are off.
    event_loop_probe: Optional[asyncio.Task] = field(default=None)
    # The aggregator the reporter flushes; flushed once more at drain so the
    # final interval is not lost with the process.
    metrics: Optional[MetricsAggregator] = field(default=None)
    audit_server: Optional[grpc.aio.Server] = field(default=None)


async def _dependency_health_loop(
    health_servicer: health.aio.HealthServicer,
    dependency: _DependencyHealth,
    *,
    interval_seconds: float,
    timeout_seconds: float,
    failure_threshold: int,
    can_serve_without_dependency: Optional[Callable[[], bool]] = None,
) -> None:
    """Drive the ``readiness`` gRPC health service from Redis health.

    A Portunus whose loop is alive but whose Redis is unreachable times out
    every ext_authz ``Check`` (fail-closed deny). The monitor drives only
    **readiness** so the ALB pulls the task from rotation; LIVENESS (``""``) is
    left alone because on a *correlated* Redis outage flipping ``""`` would make
    ECS recycle the whole fleet at once and (with Envoy dependsOn
    Portunus-HEALTHY) deadlock replacements behind the same dead Redis.
    Redis-down means "out of rotation", never "kill the task".

    Debounce: readiness flips NOT_SERVING only after ``failure_threshold``
    CONSECUTIVE failures, and back SERVING on the FIRST success. The first probe
    runs immediately (readiness starts NOT_SERVING), so a healthy boot is ready
    within one round-trip.

    ``can_serve_without_dependency`` is consulted when the probe fails: while
    it returns True (the L1 auth cache still holds servable entries) the probe
    counts as a success. Otherwise a correlated Redis blip pulls every task out
    of rotation at once, even though each could keep serving its cached
    principals — turning a partial degradation into a full outage.

    ``stop_grpc_server`` cancels this task *before* flipping the drain's
    NOT_SERVING, so the monitor can never resurrect a draining task.
    """
    ready: Optional[bool] = None  # unknown until the first probe completes
    consecutive_failures = 0
    while True:
        ok = False
        try:
            async with asyncio.timeout(timeout_seconds):
                ok = await dependency.health_check()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Dependency health check raised: %s", type(e).__name__)
            ok = False

        if not ok and can_serve_without_dependency is not None:
            try:
                ok = can_serve_without_dependency()
            except Exception as e:
                logger.warning("Serve-without-dependency check raised: %s", e)
            if ok:
                logger.warning(
                    "Dependency health check failed; staying ready on the local "
                    "auth cache",
                    extra={"event": "dependency_health_degraded"},
                )

        if ok:
            consecutive_failures = 0
            if ready is not True:
                ready = True
                await health_servicer.set(
                    READINESS_SERVICE_NAME, health_pb2.HealthCheckResponse.SERVING
                )
                logger.info(
                    "Dependency health OK; readiness SERVING (back in rotation)"
                )
        else:
            consecutive_failures += 1
            if ready is not False and consecutive_failures >= failure_threshold:
                ready = False
                await health_servicer.set(
                    READINESS_SERVICE_NAME,
                    health_pb2.HealthCheckResponse.NOT_SERVING,
                )
                logger.error(
                    "Dependency health check failed %d consecutive times "
                    "(Redis unreachable): readiness NOT_SERVING — this task "
                    "would fail-closed deny every Check, so it leaves ALB "
                    "rotation (liveness unaffected; the task is NOT recycled)",
                    consecutive_failures,
                    extra={"event": "dependency_health_not_serving"},
                )

        await asyncio.sleep(interval_seconds)


def register_audit_metrics(
    metrics: MetricsAggregator,
    publish_queue: BoundedPublishQueue,
    proc_servicer: PortunusProcessServicer,
    publish_service: Optional[PublishService],
) -> None:
    """Register the ext_proc (audit) metric sources on ``metrics``.

    The publish queue and publish service already keep cumulative counters,
    so they are registered as delta sources rather than being taught to call
    the aggregator on their own hot paths.

    Args:
        metrics: The aggregator to register against.
        publish_queue: Queue whose counters and depth are reported.
        proc_servicer: Servicer whose active-stream count is gauged.
        publish_service: Firehose client wrapper; None skips its counters
            (tests, and any future queue without a service behind it).
    """
    metrics.register_delta_source(
        lambda: {
            SUBMITTED_RECORDS: publish_queue.submitted_total,
            PUBLISHED_RECORDS: publish_queue.published_total,
            DROPPED_RECORDS: publish_queue.dropped_total,
            BUILD_FAILED_RECORDS: publish_queue.build_failed_total,
            DELIVERY_FAILED_RECORDS: publish_queue.delivery_failed_total,
            SKIPPED_UNCONFIGURED_RECORDS: publish_queue.skipped_unconfigured_total,
            SENTINEL_DROPPED_RECORDS: publish_queue.sentinel_dropped_total,
        }
    )
    if publish_service is not None:
        metrics.register_delta_source(
            lambda: {
                FIREHOSE_THROTTLED_RECORDS: publish_service.throttled_total,
                FIREHOSE_PUT_ERRORS: publish_service.put_errors_total,
            }
        )
    metrics.register_gauge_source(
        lambda: {
            PUBLISH_QUEUE_DEPTH: publish_queue.qsize(),
            PUBLISH_QUEUE_BYTES: publish_queue.queued_bytes,
            ACTIVE_EXT_PROC_STREAMS: proc_servicer.active_stream_count,
        }
    )


def register_auth_metrics(
    metrics: MetricsAggregator, auth_service: AuthService
) -> None:
    """Register the ext_authz metric sources on ``metrics``.

    Check outcomes, Redis-cache outcomes and full-auth timings are counted
    inline by the servicer and the auth service; only the L1 cache keeps its
    own cumulative counters, so only it needs a delta source.

    Args:
        metrics: The aggregator to register against.
        auth_service: Service owning the L1 auth cache.
    """
    local_cache = getattr(auth_service, "local_cache", None)
    if local_cache is None:
        return
    metrics.register_delta_source(
        lambda: {
            AUTH_L1_HIT: local_cache.hits_total,
            AUTH_L1_STALE_SERVED: local_cache.stale_served_total,
            AUTH_L1_MISS: local_cache.misses_total,
            AUTH_L1_COALESCED: local_cache.coalesced_total,
        }
    )


async def _event_loop_lag_probe(
    metrics: MetricsAggregator, *, interval_seconds: float
) -> None:
    """Sample how late the event loop wakes a fixed-length sleep.

    Drift between the requested sleep and the elapsed time is the loop's
    scheduling backlog: the single number that says whether a latency spike
    is Portunus being CPU-starved (a blocking call on the loop, a GC pause,
    a throttled task) rather than a slow dependency. Samples land in the
    ``EventLoopLag`` distribution, so CloudWatch reports the interval's max
    and average without an EMF line per probe.

    Args:
        metrics: Aggregator receiving the samples.
        interval_seconds: Nominal sleep between samples.
    """
    loop = asyncio.get_running_loop()
    while True:
        before = loop.time()
        await asyncio.sleep(interval_seconds)
        lag_ms = (loop.time() - before - interval_seconds) * 1000
        if lag_ms > 0:
            metrics.observe(EVENT_LOOP_LAG, lag_ms)


async def _metrics_reporter_loop(
    metrics: MetricsAggregator, *, interval_seconds: float
) -> None:
    """Flush the aggregated interval as EMF every ``interval_seconds``.

    Metrics must never take the server down: ``flush`` swallows its own
    failures, and anything else non-cancellation is logged and the loop
    continues.

    Args:
        metrics: Aggregator to flush.
        interval_seconds: Flush period.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            metrics.flush()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Metrics emission failed: %s", type(e).__name__)


async def start_grpc_server(
    *,
    config: GrpcConfig,
    firehose: FirehoseConfig,
    auth_service: AuthService,
    publish_service: PublishService,
    metrics_config: Optional[MetricsConfig] = None,
) -> Optional[GrpcRuntime]:
    """Start the Portunus gRPC server.

    Registers ext_authz, ext_proc, the health service, and reflection. Returns
    None when ``config.enabled`` is False.

    ``metrics_config`` defaults to a disabled :class:`MetricsConfig`, so an
    embedded server (tests, local harnesses) never writes EMF to stdout
    unless it asks to.

    Raises ``RuntimeError`` when the channel-identity key or the Firehose audit
    sink is misconfigured, so a task that would accept unauthenticated callers
    or silently drop all audit records never comes up serving.
    """
    if not config.enabled:
        logger.info("gRPC server disabled (config.grpc.enabled=false); skipping start")
        return None

    # Fail closed if the channel-identity gate is silently off: an empty
    # ``proxy_api_key`` makes ``is_valid_proxy_key`` accept every caller.
    # Require explicit GRPC_PROXY_API_KEY_OPTIONAL=true to opt in.
    if not config.proxy_api_key and not config.proxy_api_key_optional:
        raise RuntimeError(
            "GRPC_PROXY_API_KEY is empty and GRPC_PROXY_API_KEY_OPTIONAL "
            "is not set to true. Refusing to start the gRPC server "
            "without a channel-identity key. Set GRPC_PROXY_API_KEY to "
            "the pre-shared key the Envoy proxy injects via "
            "x-portunus-proxy-key initial_metadata, or set "
            "GRPC_PROXY_API_KEY_OPTIONAL=true to acknowledge that the "
            "channel-identity gate is disabled (local dev / tests "
            "only)."
        )

    # A trivial key (1-char placeholder, stray whitespace) passes the empty-key
    # guard but is no real gate. Require a minimum length so a fat-fingered
    # deployment fails at boot, not in a security review.
    if (
        config.proxy_api_key
        and len(config.proxy_api_key.encode("utf-8")) < _MIN_PROXY_KEY_BYTES
    ):
        raise RuntimeError(
            f"GRPC_PROXY_API_KEY is only {len(config.proxy_api_key.encode('utf-8'))} "
            f"bytes; refusing to start with a key shorter than "
            f"{_MIN_PROXY_KEY_BYTES} bytes. A trivially short pre-shared key "
            "gives a false sense of a channel-identity gate."
        )

    # Fail fast if the Firehose audit sink is misconfigured: each ``build_*``
    # short-circuits to ``None`` (warning only) when its stream is unset, so a
    # task with ``FIREHOSE_*`` unset would serve while silently dropping all
    # audit records. Refuse to serve instead — there is no opt-out.
    # An auth-only process never publishes, so it needs no Firehose config.
    missing_streams = (
        firehose.missing_required_streams() if config.role != "auth" else []
    )
    if missing_streams:
        raise RuntimeError(
            "Refusing to start the gRPC server: Firehose audit publishing is "
            "misconfigured. Missing required delivery stream env vars: "
            f"{', '.join(missing_streams)}. Serving with these unset would "
            "silently drop 100% of audit records while reporting success "
            "(most likely a task still carrying the pre-migration KINESIS_* "
            "env vars)."
        )

    serves_auth = config.role in ("all", "auth")
    serves_audit = config.role in ("all", "audit")
    if config.role == "all" and config.audit_port == config.port:
        raise RuntimeError("Authentication and audit listeners need distinct ports")
    # An audit-only process listens where Envoy's ext_proc cluster points: the
    # audit port when one is configured, else the single gRPC port.
    listen_port = (
        config.audit_port
        if config.role == "audit" and config.audit_port is not None
        else config.port
    )
    options = [
        ("grpc.max_concurrent_streams", config.max_concurrent_streams),
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.max_send_message_length", _MAX_GRPC_MSG_BYTES),
        ("grpc.max_receive_message_length", _MAX_GRPC_MSG_BYTES),
    ]
    server = grpc.aio.server(options=options)
    audit_server = (
        grpc.aio.server(options=options)
        if config.role == "all" and config.audit_port is not None
        else None
    )

    auth_servicer = PortunusAuthServicer(
        auth_service=auth_service,
        sign_request_fn=sign_request,
    )
    if serves_auth:
        external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
            auth_servicer, server
        )

    publish_queue = BoundedPublishQueue(
        maxsize=config.publish_queue_maxsize,
        body_capacity=config.publish_queue_body_capacity,
        # Byte budget alongside the record-count cap: each body task retains its
        # raw chunk by closure, so the record count alone (10k × ~750 KB ≈
        # 6.4 GiB) would blow past the container memory cap.
        max_bytes=config.publish_queue_max_bytes,
        num_workers=(
            config.publish_workers
            if config.publish_workers is not None
            else max(4, config.max_concurrent_streams // 64)
        ),
        max_batch=config.publish_batch_size,
        coalesce_seconds=config.publish_coalesce_ms / 1000,
        drop_on_pressure=config.audit_drop_on_pressure,
        # Workers drain in stream-grouped Firehose PutRecordBatch calls, keeping
        # records/s under the per-stream quota without an unbounded buffer.
        batch_sender=publish_service.put_record_batch,
    )
    await publish_queue.start()

    proc_servicer = PortunusProcessServicer(
        publish_service=publish_service,
        publish_queue=publish_queue,
    )
    if serves_audit:
        proc_grpc.add_ExternalProcessorServicer_to_server(
            proc_servicer, audit_server if audit_server is not None else server
        )

    # Standard gRPC health service — the ECS / ALB probe target.
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Server reflection so operators can introspect the server without a local
    # .proto copy.
    reflection.enable_server_reflection(
        (
            *(
                (
                    external_auth_pb2.DESCRIPTOR.services_by_name[
                        "Authorization"
                    ].full_name,
                )
                if serves_auth
                else ()
            ),
            *(
                (proc_pb2.DESCRIPTOR.services_by_name["ExternalProcessor"].full_name,)
                if serves_audit and audit_server is None
                else ()
            ),
            health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
            reflection.SERVICE_NAME,
        ),
        server,
    )

    listen_addr = f"{config.host}:{listen_port}"
    try:
        server.add_insecure_port(listen_addr)
        if audit_server is not None:
            audit_server.add_insecure_port(f"{config.host}:{config.audit_port}")
            await audit_server.start()
        await server.start()
    except BaseException:
        await asyncio.gather(
            server.stop(0),
            *([audit_server.stop(0)] if audit_server is not None else []),
        )
        await publish_queue.stop(drain_timeout=0)
        raise

    # Mark liveness SERVING only after the listener is up, so a probe can't see
    # SERVING before the port accepts connections. It stays SERVING until drain
    # start; the Redis monitor never touches it, so a dependency outage can
    # never make ECS recycle the task.
    await health_servicer.set(
        LIVENESS_SERVICE_NAME, health_pb2.HealthCheckResponse.SERVING
    )

    # Surface Redis health into the READINESS service (ALB /healthz target): a
    # task that is alive but would fail-closed deny every Check (Redis down)
    # leaves rotation instead of 403ing traffic invisibly — without being
    # killed. Readiness starts NOT_SERVING; the monitor's immediate first probe
    # proves it.
    health_monitor: Optional[asyncio.Task] = None
    dependency = getattr(publish_service, "state_service", None)
    if (
        serves_auth
        and config.health_check_interval_seconds > 0
        and dependency is not None
        and hasattr(dependency, "health_check")
    ):
        await health_servicer.set(
            READINESS_SERVICE_NAME, health_pb2.HealthCheckResponse.NOT_SERVING
        )
        health_monitor = asyncio.create_task(
            _dependency_health_loop(
                health_servicer,
                dependency,
                interval_seconds=config.health_check_interval_seconds,
                timeout_seconds=config.health_check_timeout_seconds,
                failure_threshold=config.health_check_failure_threshold,
                can_serve_without_dependency=getattr(
                    auth_service, "has_servable_cache_entries", None
                ),
            ),
            name="dependency-health-monitor",
        )
    else:
        # No monitor to drive readiness — report SERVING unconditionally so a
        # monitor-disabled deployment (tests, local dev) still passes the
        # /healthz-gated probes. An audit-only process has no Redis dependency
        # (it never authenticates), so it is ready once listening.
        await health_servicer.set(
            READINESS_SERVICE_NAME, health_pb2.HealthCheckResponse.SERVING
        )
    if health_monitor is None and serves_auth:
        logger.warning(
            "Dependency health monitor disabled "
            "(interval=%s, state_service available=%s) — the readiness "
            "health service will not reflect Redis outages",
            config.health_check_interval_seconds,
            dependency is not None,
        )

    logger.info(
        "gRPC server listening on %s (role=%s, max_concurrent_streams=%d)",
        listen_addr,
        config.role,
        config.max_concurrent_streams,
    )
    # CloudWatch EMF. Each role registers only the sources it owns, so a
    # split deployment emits every metric from exactly one process instead of
    # the idle half dragging averages down with structural zeroes.
    metrics_config = metrics_config or MetricsConfig()
    metrics = configure_metrics(
        enabled=metrics_config.enabled,
        namespace=metrics_config.namespace,
        service_name=metrics_config.service_name,
        role=config.role,
    )
    metrics_reporter: Optional[asyncio.Task] = None
    event_loop_probe: Optional[asyncio.Task] = None
    if metrics.enabled:
        if serves_auth:
            register_auth_metrics(metrics, auth_service)
        if serves_audit:
            register_audit_metrics(
                metrics, publish_queue, proc_servicer, publish_service
            )
        metrics_reporter = asyncio.create_task(
            _metrics_reporter_loop(
                metrics, interval_seconds=metrics_config.flush_interval_seconds
            ),
            name="metrics-reporter",
        )
        if metrics_config.event_loop_probe_seconds > 0:
            event_loop_probe = asyncio.create_task(
                _event_loop_lag_probe(
                    metrics,
                    interval_seconds=metrics_config.event_loop_probe_seconds,
                ),
                name="event-loop-lag-probe",
            )
        logger.info(
            "CloudWatch EMF metrics enabled (namespace=%s, service=%s, "
            "role=%s, flush=%.0fs)",
            metrics_config.namespace,
            metrics_config.service_name,
            config.role,
            metrics_config.flush_interval_seconds,
        )

    return GrpcRuntime(
        server=server,
        proc_servicer=proc_servicer,
        publish_queue=publish_queue,
        publish_service=publish_service,
        health_servicer=health_servicer,
        health_monitor=health_monitor,
        metrics_reporter=metrics_reporter,
        event_loop_probe=event_loop_probe,
        metrics=metrics if metrics.enabled else None,
        audit_server=audit_server,
    )


async def stop_grpc_server(
    runtime: Optional[GrpcRuntime],
    grace_seconds: int,
    *,
    flush_reserve_seconds: float = 5.0,
) -> None:
    """Stop the gRPC server, drain the publish queue, close the AWS client.

    ``server.stop(grace=N)`` waits up to N seconds for active streams.
    Completed HTTP capture ends after both directions finish; unfinished HTTP
    and successful WebSocket streams may remain open until the deadline.
    Reserve part of the shared deadline to flush their queued audit records
    after cancellation, even when those streams use the full drain budget.
    These phases share ``grace_seconds``. Running
    signing threads can still delay process exit beyond the coroutine's drain
    budget; their SDK I/O limits constrain ordinary network stalls, not arbitrary
    thread hangs.
    """
    if runtime is None:
        return
    logger.info(
        "gRPC drain starting: %d active streams, %ds grace "
        "(%.1fs reserved for the audit flush)",
        runtime.proc_servicer.active_stream_count,
        grace_seconds,
        min(flush_reserve_seconds, grace_seconds),
    )

    # Stop the health monitor FIRST so it can't race the drain and flip
    # readiness back to SERVING after we mark NOT_SERVING below.
    if runtime.health_monitor is not None:
        runtime.health_monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await runtime.health_monitor

    # Stop the reporter and the probe before draining, then flush once at the
    # very end (below) so the final partial interval — including whatever the
    # drain itself reports — still reaches CloudWatch.
    for task in (runtime.metrics_reporter, runtime.event_loop_probe):
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    # Flip BOTH health services to NOT_SERVING so an in-flight probe sees the
    # drain immediately: readiness stops routing new connections, and liveness
    # reflects intentional shutdown (the one case where the task going away is
    # the point).
    await runtime.health_servicer.set(
        READINESS_SERVICE_NAME, health_pb2.HealthCheckResponse.NOT_SERVING
    )
    await runtime.health_servicer.set(
        LIVENESS_SERVICE_NAME, health_pb2.HealthCheckResponse.NOT_SERVING
    )

    # Share a SINGLE drain budget across both stops: a full grace each would let
    # a wedged sink + active stream consume up to 2×grace, risking SIGKILL (137)
    # if grace approaches the ECS ``stopTimeout``. The server drain gets grace
    # minus the flush reserve, the queue gets what remains, so the total stays
    # bounded by ``grace_seconds`` and the flush is never starved to zero.
    loop = asyncio.get_running_loop()
    reserve = min(max(0.0, flush_reserve_seconds), float(grace_seconds))
    deadline = loop.time() + grace_seconds

    servers = [runtime.server]
    if runtime.audit_server is not None:
        servers.append(runtime.audit_server)
    await asyncio.gather(
        *(server.stop(grace=max(0.0, grace_seconds - reserve)) for server in servers)
    )

    # The queue gets the remaining grace to flush to Firehose — accepted
    # records should not be dropped while grace remains. ``stop`` reports how
    # many accepted records it had to cancel so the loss is observable.
    queue_drain_budget = max(0.0, deadline - loop.time())
    cancelled = await runtime.publish_queue.stop(drain_timeout=queue_drain_budget)
    if cancelled:
        # ERROR, not WARNING: a clean ``exit 0`` would otherwise mask audit
        # loss. The ``extra`` fields give a stable key
        # (``event=audit_records_lost_on_drain``) for a CloudWatch alarm.
        logger.error(
            "AUDIT LOSS on drain: %d accepted audit records were never "
            "flushed within the %.1fs flush window of the %ds grace "
            "(flush budget exhausted — sink wedged/slow, or too much "
            "buffered for the window); they are permanently lost",
            cancelled,
            queue_drain_budget,
            grace_seconds,
            extra={
                "event": "audit_records_lost_on_drain",
                "lost_audit_records": cancelled,
                "grace_seconds": grace_seconds,
                "flush_budget_seconds": queue_drain_budget,
            },
        )

    # Bound the coroutine's wait; Python still joins running threads at exit.
    # SDK I/O limits constrain ordinary stalls, not arbitrary worker hangs.
    teardown_budget = max(0.0, deadline - loop.time())
    torn_down = False
    if teardown_budget > 0:
        try:
            async with asyncio.timeout(teardown_budget):
                await asyncio.to_thread(reset_signing_runtime, wait=True)
            torn_down = True
        except TimeoutError:
            logger.warning(
                "KMS signing executor did not shut down within the "
                "remaining %.1fs drain budget; continuing the async drain "
                "while running workers may still delay process exit",
                teardown_budget,
            )
    if not torn_down:
        reset_signing_runtime(wait=False)

    try:
        await runtime.publish_service.state_service.close()
    except AttributeError:
        pass

    logger.info(
        "gRPC drain complete: submitted=%d published=%d queue_dropped=%d "
        "delivery_failed=%d build_failed=%d skipped_unconfigured=%d "
        "drain_cancelled=%d",
        runtime.publish_queue.submitted_total,
        runtime.publish_queue.published_total,
        runtime.publish_queue.dropped_total,
        runtime.publish_queue.delivery_failed_total,
        runtime.publish_queue.build_failed_total,
        runtime.publish_queue.skipped_unconfigured_total,
        runtime.publish_queue.cancelled_total,
    )

    # Final flush AFTER the drain accounting above: the last interval's
    # counters (including the drain's own drops) would otherwise die with
    # the process.
    if runtime.metrics is not None:
        runtime.metrics.flush()


async def run() -> None:
    """Process entrypoint: build services, serve gRPC, drain on SIGTERM.

    Blocks until SIGTERM/SIGINT, then drains gracefully.
    The container stop timeout must exceed graceful_shutdown_seconds.
    """
    # Imported here, not at module top, so importing this module for its
    # start/stop helpers (e.g. in tests) doesn't construct AWS/Redis clients.
    import portunus.logging  # noqa: F401 — import side effect: configures logging
    from portunus.config import config
    from portunus.services.auth_service import AuthService
    from portunus.services.cache_service import CacheService
    from portunus.services.publish_service import PublishService
    from portunus.services.state_service import StateService

    state_service = StateService()
    cache_service = CacheService(state_service=state_service)
    publish_service = PublishService(state_service=state_service)
    auth_service = AuthService(cache_service=cache_service)

    runtime = await start_grpc_server(
        config=config.grpc,
        firehose=config.firehose,
        auth_service=auth_service,
        publish_service=publish_service,
        metrics_config=config.metrics,
    )
    if runtime is None:
        logger.error(
            "gRPC server disabled (GRPC_ENABLED=false) but it is now the "
            "only Portunus surface; nothing to serve. Exiting."
        )
        return

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    logger.info("Portunus gRPC process ready; awaiting termination signal")
    await stop_event.wait()
    logger.info("Termination signal received; draining")

    await stop_grpc_server(
        runtime,
        grace_seconds=config.grpc.graceful_shutdown_seconds,
        flush_reserve_seconds=config.grpc.drain_flush_reserve_seconds,
    )
    await state_service.close_redis_client()
    logger.info("Portunus gRPC process shut down cleanly")


def main() -> None:
    """Console / ``python -m portunus.grpc.server`` entrypoint."""
    run_event_loop(run())


if __name__ == "__main__":
    main()
