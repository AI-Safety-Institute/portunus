"""gRPC server lifecycle for Portunus's Envoy filter services.

Starts and stops the gRPC server alongside the existing FastAPI app.
Lifecycle is hooked into FastAPI's ``lifespan`` so the gRPC server
starts when uvicorn / gunicorn does and stops cleanly on SIGTERM.

The gRPC server runs in the same asyncio event loop as FastAPI via
``grpc.aio`` — not the threaded ``grpcio.server`` — so the existing
:class:`portunus.services.auth_service.AuthService` and friends can be
called directly without ``run_in_executor`` wrappers.

Default-off: :attr:`portunus.config.GrpcConfig.enabled` must be true for
:func:`start_grpc_server` to bind a port. Otherwise it logs a no-op and
returns ``None``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import grpc
from envoy.service.auth.v3 import external_auth_pb2_grpc  # type: ignore[import-not-found]
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc  # type: ignore[import-not-found]

from portunus.config import GrpcConfig
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.grpc.publish_queue import BoundedPublishQueue
from portunus.services.auth_service import AuthService
from portunus.services.publish_service import PublishService
from portunus.services.signing_service import sign_request

logger = logging.getLogger("api.grpc")


@dataclass
class GrpcRuntime:
    """Aggregates the gRPC server and the components that need orderly shutdown.

    The drain handler iterates ``proc_servicer.drain_all()`` to inject WS
    close frames into active ext_proc streams, then stops the publish
    queue (waiting for in-flight publishes to finish), then stops the
    gRPC server with a grace period.
    """

    server: grpc.aio.Server
    proc_servicer: PortunusProcessServicer
    publish_queue: BoundedPublishQueue


async def start_grpc_server(
    *,
    config: GrpcConfig,
    auth_service: AuthService,
    publish_service: PublishService,
) -> Optional[GrpcRuntime]:
    """Start the Portunus gRPC server with ext_authz + ext_proc registered.

    If :attr:`config.enabled` is False, returns ``None`` immediately
    without binding a port.

    Args:
        config: gRPC server configuration.
        auth_service: Existing auth service; the Check servicer wraps it.
        publish_service: Existing publish service; both servicers use it.

    Returns:
        A :class:`GrpcRuntime` holding the server, ext_proc servicer
        (for drain coordination), and publish queue; or ``None`` when
        the feature flag is off.
    """
    if not config.enabled:
        logger.info(
            "gRPC server disabled (config.grpc.enabled=false); skipping start"
        )
        return None

    server = grpc.aio.server(
        options=[
            ("grpc.max_concurrent_streams", config.max_concurrent_streams),
            # HTTP/2 keepalive so Envoy's long-lived connection pool doesn't
            # time out the multiplexed control stream during quiet periods.
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", 1),
        ]
    )

    auth_servicer = PortunusAuthServicer(
        auth_service=auth_service,
        publish_service=publish_service,
        sign_request_fn=sign_request,
    )
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(auth_servicer, server)

    # Bounded publish queue. Size = 30s of typical body throughput; tune
    # per-tenant once we have real-traffic load tests. Workers = same
    # heuristic as the existing relay log queue.
    publish_queue = BoundedPublishQueue(
        maxsize=10_000,
        num_workers=max(4, config.max_concurrent_streams // 64),
    )
    await publish_queue.start()

    proc_servicer = PortunusProcessServicer(
        publish_service=publish_service,
        publish_queue=publish_queue,
    )
    proc_grpc.add_ExternalProcessorServicer_to_server(proc_servicer, server)

    listen_addr = f"[::]:{config.port}"
    server.add_insecure_port(listen_addr)
    await server.start()
    logger.info(
        "gRPC server listening on %s (max_concurrent_streams=%d)",
        listen_addr,
        config.max_concurrent_streams,
    )
    return GrpcRuntime(
        server=server,
        proc_servicer=proc_servicer,
        publish_queue=publish_queue,
    )


async def stop_grpc_server(
    runtime: Optional[GrpcRuntime],
    grace_seconds: int,
) -> None:
    """Stop the gRPC server with a coordinated drain.

    Order matters:

    1. Signal every active ext_proc stream to inject a WS close-code
       1012. Clients reconnect to surviving Portunus tasks.
    2. Stop the gRPC server with ``grace_seconds`` for in-flight RPCs
       to finish naturally — short-lived HTTP ext_authz / ext_proc
       calls complete; long-lived WS ext_proc streams either finish
       on the close-frame or get force-cancelled at the deadline.
    3. Drain the publish queue so any in-flight body publishes
       complete (or timeout).
    """
    if runtime is None:
        return
    logger.info(
        "gRPC drain starting: %d active streams, %ds grace",
        runtime.proc_servicer.active_stream_count,
        grace_seconds,
    )

    await runtime.proc_servicer.drain_all()
    await runtime.server.stop(grace=grace_seconds)
    await runtime.publish_queue.stop(drain_timeout=min(5.0, float(grace_seconds)))

    logger.info(
        "gRPC drain complete: %d records published, %d dropped",
        runtime.publish_queue.published_total,
        runtime.publish_queue.dropped_total,
    )
