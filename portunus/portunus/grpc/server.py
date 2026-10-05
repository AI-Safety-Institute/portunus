"""gRPC service assembly, health reporting, and process lifecycle."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from dataclasses import dataclass
from typing import Optional

import grpc
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from portunus.config import GrpcConfig
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.services.auth_service import AuthService

if sys.platform not in {"win32", "cygwin"} and sys.implementation.name == "cpython":
    from uvloop import run as run_event_loop
else:
    from asyncio import run as run_event_loop

logger = logging.getLogger("api.grpc")

# Minimum proxy-key length. The empty-key guard passes a 1-char placeholder
# that gives no real channel-identity protection — refuse it too.
_MIN_PROXY_KEY_BYTES = 16


@dataclass
class GrpcRuntime:
    """Aggregates the gRPC server and components needing orderly shutdown."""

    server: grpc.aio.Server
    health_servicer: health.aio.HealthServicer


async def start_grpc_server(
    *,
    config: GrpcConfig,
    auth_service: AuthService,
) -> Optional[GrpcRuntime]:
    """Start the Portunus gRPC server.

    Registers ext_authz, the health service, and reflection. Returns None when
    ``config.enabled`` is False.

    Raises ``RuntimeError`` when the channel-identity key is misconfigured, so
    a task that would accept unauthenticated callers never comes up serving.
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

    options = [
        ("grpc.max_concurrent_streams", config.max_concurrent_streams),
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.keepalive_permit_without_calls", 1),
    ]
    server = grpc.aio.server(options=options)

    auth_servicer = PortunusAuthServicer(auth_service=auth_service)
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(auth_servicer, server)

    # Standard gRPC health service — the one health signal (default service
    # ""), read by the container probe.
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Server reflection so operators can introspect the listener without a
    # local .proto copy.
    auth_service_name = external_auth_pb2.DESCRIPTOR.services_by_name[
        "Authorization"
    ].full_name
    health_service_name = health_pb2.DESCRIPTOR.services_by_name["Health"].full_name
    reflection.enable_server_reflection(
        (auth_service_name, health_service_name, reflection.SERVICE_NAME),
        server,
    )

    listen_addr = f"{config.host}:{config.port}"
    try:
        server.add_insecure_port(listen_addr)
        await server.start()
    except BaseException:
        await server.stop(0)
        raise

    # SERVING only once the listener is up, NOT_SERVING from drain start.
    # Deliberately not tied to Redis or any other shared dependency: every task
    # shares one Redis, so a Redis-gated health signal would pull the whole
    # fleet out of rotation at once and turn a Redis problem into a total
    # outage.
    await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)

    logger.info(
        "gRPC server listening on %s (max_concurrent_streams=%d)",
        listen_addr,
        config.max_concurrent_streams,
    )
    return GrpcRuntime(server=server, health_servicer=health_servicer)


async def stop_grpc_server(
    runtime: Optional[GrpcRuntime],
    grace_seconds: int,
) -> None:
    """Stop the gRPC server, waiting up to ``grace_seconds`` for active RPCs."""
    if runtime is None:
        return
    logger.info("gRPC drain starting: %ds grace", grace_seconds)

    # NOT_SERVING first so a probe sees the drain immediately and the load
    # balancer stops routing new connections here.
    await runtime.health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
    await runtime.server.stop(grace=grace_seconds)
    logger.info("gRPC drain complete")


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
    from portunus.services.state_service import StateService

    state_service = StateService()
    cache_service = CacheService(state_service=state_service)
    auth_service = AuthService(cache_service=cache_service)

    runtime = await start_grpc_server(config=config.grpc, auth_service=auth_service)
    if runtime is None:
        logger.error(
            "gRPC server disabled (GRPC_ENABLED=false); nothing to serve. Exiting."
        )
        return

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    logger.info("Portunus gRPC process ready; awaiting termination signal")
    await stop_event.wait()
    logger.info("Termination signal received; draining")

    await stop_grpc_server(runtime, grace_seconds=config.grpc.graceful_shutdown_seconds)
    await auth_service.mint_service.aclose()
    await state_service.close_redis_client()
    logger.info("Portunus gRPC process shut down cleanly")


def main() -> None:
    """Console / ``python -m portunus.grpc.server`` entrypoint."""
    run_event_loop(run())


if __name__ == "__main__":
    main()
