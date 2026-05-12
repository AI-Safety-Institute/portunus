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
from typing import Optional

import grpc
from envoy.service.auth.v3 import external_auth_pb2_grpc  # type: ignore[import-not-found]

from portunus.config import GrpcConfig
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.services.auth_service import AuthService
from portunus.services.publish_service import PublishService
from portunus.services.signing_service import sign_request

logger = logging.getLogger("api.grpc")


async def start_grpc_server(
    *,
    config: GrpcConfig,
    auth_service: AuthService,
    publish_service: PublishService,
) -> Optional[grpc.aio.Server]:
    """Start the Portunus gRPC server.

    If :attr:`config.enabled` is False, returns ``None`` immediately
    without binding a port. This keeps existing deployments unaffected
    until they explicitly turn the gRPC server on.

    Args:
        config: gRPC server configuration.
        auth_service: Existing auth service; the Check servicer wraps it.
        publish_service: Existing publish service; the Check servicer
            uses it to publish principal metadata synchronously.

    Returns:
        The running ``grpc.aio.Server`` instance, or ``None`` if the
        feature flag is off. Caller is responsible for calling
        :func:`stop_grpc_server` on the returned server.
    """
    if not config.enabled:
        logger.info(
            "gRPC server disabled (config.grpc.enabled=false); skipping start"
        )
        return None

    server = grpc.aio.server(
        options=[
            ("grpc.max_concurrent_streams", config.max_concurrent_streams),
            # Enable HTTP/2 keepalive so Envoy's long-lived connection pool
            # doesn't time out the multiplexed control stream during quiet
            # periods. Defaults are conservative; align with Envoy's
            # connection-pool defaults (5s) so we never close first.
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

    listen_addr = f"[::]:{config.port}"
    server.add_insecure_port(listen_addr)
    await server.start()
    logger.info(
        "gRPC server listening on %s (max_concurrent_streams=%d)",
        listen_addr,
        config.max_concurrent_streams,
    )
    return server


async def stop_grpc_server(
    server: Optional[grpc.aio.Server],
    grace_seconds: int,
) -> None:
    """Stop the gRPC server, giving in-flight RPCs ``grace_seconds`` to finish.

    A ``None`` server (the default-off case) is a no-op. After ``grace_seconds``,
    any remaining streams are force-cancelled.

    """
    if server is None:
        return
    logger.info("gRPC server stopping with %ds grace period", grace_seconds)
    await server.stop(grace=grace_seconds)
    logger.info("gRPC server stopped")
