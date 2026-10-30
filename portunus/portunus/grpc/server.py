"""gRPC service assembly, health reporting, and process lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from dataclasses import dataclass, field
from typing import Optional

import grpc
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from portunus.config import GrpcConfig, KinesisConfig, MetricsConfig
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.metrics import (
    EVENT_LOOP_LAG,
    PUBLISH_QUEUE_DEPTH,
    MetricsAggregator,
    configure_metrics,
)
from portunus.services.auth_service import AuthService
from portunus.services.publish_queue import BoundedPublishQueue
from portunus.services.publish_service import PublishService

if sys.platform not in {"win32", "cygwin"} and sys.implementation.name == "cpython":
    from uvloop import run as run_event_loop
else:
    from asyncio import run as run_event_loop

logger = logging.getLogger("api.grpc")

# ext_proc streams body chunks of up to Envoy's per-connection buffer
# (``per_connection_buffer_limit_bytes``, 50 MiB in envoy.yaml); headers and
# protobuf framing ride on top, so the gRPC message limit needs headroom.
_MAX_GRPC_MSG_BYTES = 64 * 1024 * 1024

# Minimum proxy-key length. The empty-key guard passes a 1-char placeholder
# that gives no real channel-identity protection — refuse it too.
_MIN_PROXY_KEY_BYTES = 16


@dataclass
class GrpcRuntime:
    """Aggregates the gRPC server and components needing orderly shutdown."""

    server: grpc.aio.Server
    proc_servicer: PortunusProcessServicer
    publish_queue: BoundedPublishQueue
    publish_service: PublishService
    health_servicer: health.aio.HealthServicer
    # EMF reporter and event-loop probe; None when metrics are disabled.
    metrics_reporter: Optional[asyncio.Task] = field(default=None)
    event_loop_probe: Optional[asyncio.Task] = field(default=None)
    metrics: Optional[MetricsAggregator] = field(default=None)
    audit_server: Optional[grpc.aio.Server] = field(default=None)


async def _event_loop_lag_probe(metrics: MetricsAggregator) -> None:
    """Sample how late the loop wakes a 1 s sleep: the CPU-starvation signal."""
    loop = asyncio.get_running_loop()
    while True:
        before = loop.time()
        await asyncio.sleep(1.0)
        lag_ms = (loop.time() - before - 1.0) * 1000
        if lag_ms > 0:
            metrics.observe(EVENT_LOOP_LAG, lag_ms)


async def _metrics_reporter_loop(
    metrics: MetricsAggregator, *, interval_seconds: float
) -> None:
    """Flush the aggregated interval every ``interval_seconds``."""
    while True:
        await asyncio.sleep(interval_seconds)
        metrics.flush()


async def start_grpc_server(
    *,
    config: GrpcConfig,
    kinesis: KinesisConfig,
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

    Raises ``RuntimeError`` when the channel-identity key or the Kinesis audit
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

    # Fail fast if the Kinesis audit sink is misconfigured: each ``build_*``
    # short-circuits to ``None`` (warning only) when its stream is unset, so a
    # task with ``KINESIS_*`` unset would serve while silently dropping all
    # audit records. Refuse to serve instead — there is no opt-out.
    # An auth-only process never publishes, so it needs no Kinesis config.
    missing_streams = (
        kinesis.missing_required_streams() if config.role != "auth" else []
    )
    if missing_streams:
        raise RuntimeError(
            "Refusing to start the gRPC server: Kinesis audit publishing is "
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

    auth_servicer = PortunusAuthServicer(auth_service=auth_service)
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
        # Workers drain in stream-grouped Kinesis PutRecords calls, packing
        # records to keep KDS records/s low without an unbounded buffer.
        batch_sender=publish_service.put_records,
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

    # Standard gRPC health service — the one health signal (default service
    # ""), read by the container probe and Envoy's /healthz cluster. One
    # servicer is shared by every listener, so a probe on either port sees the
    # same state and the drain flips both together.
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    if audit_server is not None:
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, audit_server)

    # Server reflection so operators can introspect each listener without a
    # local .proto copy; each listener advertises exactly what it serves.
    auth_service_name = external_auth_pb2.DESCRIPTOR.services_by_name[
        "Authorization"
    ].full_name
    proc_service_name = proc_pb2.DESCRIPTOR.services_by_name[
        "ExternalProcessor"
    ].full_name
    health_service_name = health_pb2.DESCRIPTOR.services_by_name["Health"].full_name
    reflection.enable_server_reflection(
        (
            *((auth_service_name,) if serves_auth else ()),
            *((proc_service_name,) if serves_audit and audit_server is None else ()),
            health_service_name,
            reflection.SERVICE_NAME,
        ),
        server,
    )
    if audit_server is not None:
        reflection.enable_server_reflection(
            (proc_service_name, health_service_name, reflection.SERVICE_NAME),
            audit_server,
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

    # SERVING only once the listeners are up, NOT_SERVING from drain start.
    # Deliberately not tied to Redis or any other shared dependency: every task
    # shares one Redis, so a Redis-gated health signal would pull the whole
    # fleet out of rotation at once and turn a Redis problem into a total
    # outage. Redis trouble shows in the auth and cache metrics instead.
    await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)

    logger.info(
        "gRPC server listening on %s (role=%s, max_concurrent_streams=%d)",
        listen_addr,
        config.role,
        config.max_concurrent_streams,
    )
    # CloudWatch EMF. Each role pre-registers only the counters it owns, so a
    # split deployment never reports the other half's structural zeroes.
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
        if serves_audit:
            metrics.register_gauge(lambda: {PUBLISH_QUEUE_DEPTH: publish_queue.qsize()})
        metrics_reporter = asyncio.create_task(
            _metrics_reporter_loop(
                metrics, interval_seconds=metrics_config.flush_interval_seconds
            ),
            name="metrics-reporter",
        )
        event_loop_probe = asyncio.create_task(
            _event_loop_lag_probe(metrics), name="event-loop-lag-probe"
        )

    return GrpcRuntime(
        server=server,
        proc_servicer=proc_servicer,
        publish_queue=publish_queue,
        publish_service=publish_service,
        health_servicer=health_servicer,
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
    These phases share ``grace_seconds``.
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

    # Stop the reporter and the probe before draining, then flush once at the
    # very end (below) so the final partial interval — including whatever the
    # drain itself reports — still reaches CloudWatch.
    for task in (runtime.metrics_reporter, runtime.event_loop_probe):
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    # NOT_SERVING first so a probe sees the drain immediately and the load
    # balancer stops routing new connections here.
    await runtime.health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)

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

    # The queue gets the remaining grace to flush to Kinesis — accepted
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
        kinesis=config.kinesis,
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
    await auth_service.mint_service.aclose()
    await state_service.close_redis_client()
    logger.info("Portunus gRPC process shut down cleanly")


def main() -> None:
    """Console / ``python -m portunus.grpc.server`` entrypoint."""
    run_event_loop(run())


if __name__ == "__main__":
    main()
