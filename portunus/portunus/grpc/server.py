"""gRPC server lifecycle and process entrypoint for Portunus.

The gRPC server is the Portunus process: it serves the Envoy ext_authz /
ext_proc filters and the standard ``grpc.health.v1.Health`` +
server-reflection services. There is no HTTP / FastAPI surface — :func:`run`
owns the asyncio loop and SIGTERM-driven drain (the Dockerfile ``CMD`` is
``python -m portunus.grpc.server``).

Gated on :attr:`GrpcConfig.enabled` (default off; tests construct the runtime
directly).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from dataclasses import dataclass, field
from typing import Optional, Protocol

import grpc
from envoy.service.auth.v3 import external_auth_pb2_grpc
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from portunus.config import FirehoseConfig, GrpcConfig
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.services.auth_service import AuthService
from portunus.services.publish_queue import BoundedPublishQueue
from portunus.services.publish_service import PublishService
from portunus.services.signing_service import sign_request

logger = logging.getLogger("api.grpc")

# Envoy may buffer a 32 MiB signed request body; the full CheckRequest also
# carries headers and protobuf framing, so the gRPC receive limit needs headroom.
_MAX_GRPC_MSG_BYTES = 64 * 1024 * 1024

# Minimum length for a configured proxy key. The boot guard already refuses
# an *empty* key; a 1-char placeholder ("x", a stray space) passes that check
# while giving no real channel-identity protection — refuse it too.
_MIN_PROXY_KEY_BYTES = 16


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
    # Background task pinging Redis and flipping the gRPC health status —
    # None when the monitor is disabled or no state service is available.
    health_monitor: Optional[asyncio.Task] = field(default=None)


async def _dependency_health_loop(
    health_servicer: health.aio.HealthServicer,
    dependency: _DependencyHealth,
    *,
    interval_seconds: float,
    timeout_seconds: float,
) -> None:
    """Drive the gRPC health status from the auth path's dependencies.

    A Portunus whose event loop is alive but whose Redis is unreachable
    times out every ext_authz ``Check`` → fail-closed deny — yet the plain
    health servicer keeps answering SERVING, so the ECS ``grpc_health_probe``
    (and anything else watching gRPC health) never notices a task that is
    403ing 100% of its traffic. Ping Redis on an interval and flip the
    overall ("") status to NOT_SERVING while the dependency is down,
    SERVING again once it recovers. ``stop_grpc_server`` cancels this task
    *before* flipping NOT_SERVING for the drain, so the monitor can never
    resurrect a draining task's status.
    """
    healthy = True
    while True:
        await asyncio.sleep(interval_seconds)
        ok = False
        try:
            async with asyncio.timeout(timeout_seconds):
                ok = await dependency.health_check()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Dependency health check raised: %s", type(e).__name__)
            ok = False
        if ok and not healthy:
            healthy = True
            await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
            logger.info(
                "Dependency health recovered; gRPC health restored to SERVING"
            )
        elif not ok and healthy:
            healthy = False
            await health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
            logger.error(
                "Dependency health check failed (Redis unreachable): flipping "
                "gRPC health to NOT_SERVING — this task would fail-closed "
                "deny every Check while appearing alive",
                extra={"event": "dependency_health_not_serving"},
            )


async def start_grpc_server(
    *,
    config: GrpcConfig,
    firehose: FirehoseConfig,
    auth_service: AuthService,
    publish_service: PublishService,
) -> Optional[GrpcRuntime]:
    """Start the Portunus gRPC server.

    Registers ext_authz, ext_proc, the standard health service, and server
    reflection. Returns None when ``config.enabled`` is False.

    Refuses to start (raises ``RuntimeError``) when the channel-identity key
    or the Firehose audit sink is misconfigured, so a task that would either
    accept unauthenticated callers or silently drop 100% of audit records
    never comes up serving.
    """
    if not config.enabled:
        logger.info("gRPC server disabled (config.grpc.enabled=false); skipping start")
        return None

    # Fail closed if the channel-identity gate is silently off in what
    # looks like a production config. ``proxy_api_key`` empty makes
    # ``is_valid_proxy_key`` accept every caller; require explicit
    # GRPC_PROXY_API_KEY_OPTIONAL=true to opt in.
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

    # A configured-but-trivial key (1-char placeholder, stray whitespace)
    # passes the empty-key guard while providing no real gate. Require a
    # minimum length so a fat-fingered deployment fails at boot, not in a
    # security review.
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

    # Fail fast if the Firehose audit sink is misconfigured. Every audit
    # record type is published unconditionally, but each ``build_*`` short-
    # circuits to ``None`` (warning only) when its stream is unset, so a task
    # with ``FIREHOSE_*`` unset would serve traffic while silently dropping
    # 100% of audit records — no error to the caller, no alarm. This ports the
    # FastAPI ``lifespan`` boot-guard from #22 (commit 0c9ff50) into the gRPC
    # startup path that replaced ``app.py``: refuse to come up serving rather
    # than let a blue task drop all audit. There is no opt-out (matching #22);
    # a task that genuinely needs no audit sink should not be in rotation.
    missing_streams = firehose.missing_required_streams()
    if missing_streams:
        raise RuntimeError(
            "Refusing to start the gRPC server: Firehose audit publishing is "
            "misconfigured. Missing required delivery stream env vars: "
            f"{', '.join(missing_streams)}. Serving with these unset would "
            "silently drop 100% of audit records while reporting success "
            "(most likely a task still carrying the pre-migration KINESIS_* "
            "env vars)."
        )

    server = grpc.aio.server(
        options=[
            ("grpc.max_concurrent_streams", config.max_concurrent_streams),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", 1),
            ("grpc.max_send_message_length", _MAX_GRPC_MSG_BYTES),
            ("grpc.max_receive_message_length", _MAX_GRPC_MSG_BYTES),
        ]
    )

    auth_servicer = PortunusAuthServicer(
        auth_service=auth_service,
        sign_request_fn=sign_request,
    )
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(auth_servicer, server)

    publish_queue = BoundedPublishQueue(
        maxsize=config.publish_queue_maxsize,
        body_capacity=config.publish_queue_body_capacity,
        # Byte budget alongside the record-count cap: each queued body task
        # retains its raw chunk by closure, so 10k records × ~750 KB chunks
        # is ~6.4 GiB retained — far past the container memory cap. The byte
        # bound keeps worst-case retention inside the memory budget whatever
        # the record count.
        max_bytes=config.publish_queue_max_bytes,
        num_workers=max(4, config.max_concurrent_streams // 64),
        # Workers drain themselves in stream-grouped batches via Firehose
        # PutRecordBatch — opportunistic batching keeps records/s well under
        # the per-stream quota without an unbounded buffer.
        batch_sender=publish_service.put_record_batch,
    )
    await publish_queue.start()

    proc_servicer = PortunusProcessServicer(
        publish_service=publish_service,
        publish_queue=publish_queue,
    )
    proc_grpc.add_ExternalProcessorServicer_to_server(proc_servicer, server)

    # Standard gRPC health service — the ECS / ALB probe target now that
    # the FastAPI /ping endpoint is gone. Reports SERVING for the overall
    # server ("") once listening.
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Server reflection (the standard health service plus the reflection
    # service itself) so operators can introspect the server without
    # shipping a local .proto copy.
    reflection.enable_server_reflection(
        (
            health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
            reflection.SERVICE_NAME,
        ),
        server,
    )

    listen_addr = f"{config.host}:{config.port}"
    server.add_insecure_port(listen_addr)
    await server.start()

    # Mark serving only after the listener is up, so a probe can't see
    # SERVING before the port accepts connections.
    await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)

    # Surface dependency (Redis) health into the gRPC health status: a task
    # that is SERVING but would fail-closed deny every Check (Redis down)
    # must fail its probe rather than 403 traffic invisibly. Contract for
    # the deploy side: gRPC health "" == SERVING iff the listener is up AND
    # the last dependency probe succeeded.
    health_monitor: Optional[asyncio.Task] = None
    dependency = getattr(publish_service, "state_service", None)
    if (
        config.health_check_interval_seconds > 0
        and dependency is not None
        and hasattr(dependency, "health_check")
    ):
        health_monitor = asyncio.create_task(
            _dependency_health_loop(
                health_servicer,
                dependency,
                interval_seconds=config.health_check_interval_seconds,
                timeout_seconds=config.health_check_timeout_seconds,
            ),
            name="dependency-health-monitor",
        )
    else:
        logger.warning(
            "Dependency health monitor disabled "
            "(interval=%s, state_service available=%s) — gRPC health will "
            "not reflect Redis outages",
            config.health_check_interval_seconds,
            dependency is not None,
        )

    logger.info(
        "gRPC server listening on %s (max_concurrent_streams=%d)",
        listen_addr,
        config.max_concurrent_streams,
    )
    return GrpcRuntime(
        server=server,
        proc_servicer=proc_servicer,
        publish_queue=publish_queue,
        publish_service=publish_service,
        health_servicer=health_servicer,
        health_monitor=health_monitor,
    )


async def stop_grpc_server(
    runtime: Optional[GrpcRuntime],
    grace_seconds: int,
    *,
    flush_reserve_seconds: float = 5.0,
) -> None:
    """Stop the gRPC server, drain the publish queue, close the AWS client.

    grpc.aio's ``server.stop(grace=N)`` stops accepting new streams and
    waits up to N seconds for active ones to finish naturally. Active
    ext_proc streams end when Envoy closes them — there is no
    application-layer signal we can send into a WS tunnel from
    ``observability_mode: true``, so this is grace-then-cancel rather
    than coordinated drain.

    ``flush_reserve_seconds`` carves a slice of the grace out for the
    publish-queue flush *before* the stream drain runs. With any active
    ext_proc stream at SIGTERM (i.e. every busy stop) Envoy holds the
    stream open for its own, longer drain, so ``server.stop`` consumes its
    entire budget; without the reserve the queue would get a 0-second
    flush window and cancel every buffered audit record even with a
    perfectly healthy sink. The total remains bounded by ``grace_seconds``.
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

    # Stop the dependency health monitor FIRST: it must not race the drain
    # and flip the status back to SERVING after we mark NOT_SERVING below.
    if runtime.health_monitor is not None:
        runtime.health_monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await runtime.health_monitor

    # Flip health to NOT_SERVING so an in-flight probe (ALB/ECS)
    # sees the drain immediately and stops routing new connections here.
    await runtime.health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)

    # Share a SINGLE drain budget across both stops. ``server.stop`` and
    # ``publish_queue.stop`` were previously each passed the full
    # ``grace_seconds`` and awaited sequentially, so a wedged sink + an
    # active stream could consume up to 2×grace before returning — an
    # overrun that risks a SIGKILL (137) if an operator raises grace
    # toward the ECS ``stopTimeout``. Compute the deadline once; the server
    # drain gets grace minus the flush reserve, and the queue gets whatever
    # remains (>= the reserve when the stream drain used its full slice),
    # so the total is bounded by ``grace_seconds`` and the flush is never
    # starved to zero by Envoy-held streams.
    loop = asyncio.get_running_loop()
    reserve = min(max(0.0, flush_reserve_seconds), float(grace_seconds))
    deadline = loop.time() + grace_seconds

    await runtime.server.stop(grace=max(0.0, grace_seconds - reserve))

    # The queue gets the remaining grace to flush to Firehose — records
    # already accepted should not be dropped on shutdown while grace
    # remains. ``stop`` reports how many accepted records it had to cancel
    # (in-flight batches included) so the loss is observable.
    queue_drain_budget = max(0.0, deadline - loop.time())
    cancelled = await runtime.publish_queue.stop(drain_timeout=queue_drain_budget)
    if cancelled:
        # ERROR, not WARNING: a clean ``exit 0`` otherwise masks audit
        # loss entirely. The ``extra`` fields give a stable key
        # (``event=audit_records_lost_on_drain``) for a CloudWatch metric
        # filter / alarm — ``cancelled_total`` on the queue is the
        # in-process counter for the same loss.
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


async def run() -> None:
    """Process entrypoint: build services, serve gRPC, drain on SIGTERM.

    This is the whole Portunus process — there is no FastAPI/uvicorn layer.
    Services are constructed here (previously in the FastAPI module), the
    gRPC server is started, and we block until SIGTERM/SIGINT, then drain
    gracefully. ECS sends SIGTERM on task stop; the task ``stopTimeout``
    (120s in the akp CDK) must exceed ``graceful_shutdown_seconds``.
    """
    # Imported here, not at module top, so importing this module for its
    # start/stop helpers (e.g. in tests) doesn't construct AWS/Redis clients.
    # Importing portunus.logging runs configure_logging() (structured JSON
    # to stdout) — previously done via uvicorn's --log-config.
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
    asyncio.run(run())


if __name__ == "__main__":
    main()
