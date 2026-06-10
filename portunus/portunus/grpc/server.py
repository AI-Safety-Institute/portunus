"""gRPC server lifecycle for Portunus's Envoy filter services.

Starts the ``grpc.aio`` server in the same event loop as the FastAPI
app via ``lifespan``. Gated on :attr:`GrpcConfig.enabled` (default off).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import grpc
from envoy.service.auth.v3 import external_auth_pb2_grpc
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc

from portunus.config import GrpcConfig
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


@dataclass
class GrpcRuntime:
    """Aggregates the gRPC server and components needing orderly shutdown."""

    server: grpc.aio.Server
    proc_servicer: PortunusProcessServicer
    publish_queue: BoundedPublishQueue
    publish_service: PublishService


async def start_grpc_server(
    *,
    config: GrpcConfig,
    auth_service: AuthService,
    publish_service: PublishService,
) -> Optional[GrpcRuntime]:
    """Start the Portunus gRPC server with ext_authz + ext_proc registered.

    Returns None when ``config.enabled`` is False.
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
        maxsize=10_000,
        body_capacity=9_000,
        num_workers=max(4, config.max_concurrent_streams // 64),
    )
    await publish_queue.start()

    proc_servicer = PortunusProcessServicer(
        publish_service=publish_service,
        publish_queue=publish_queue,
    )
    proc_grpc.add_ExternalProcessorServicer_to_server(proc_servicer, server)

    listen_addr = f"{config.host}:{config.port}"
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
        publish_service=publish_service,
    )


async def stop_grpc_server(
    runtime: Optional[GrpcRuntime],
    grace_seconds: int,
) -> None:
    """Stop the gRPC server, drain the publish queue, close the AWS client.

    grpc.aio's ``server.stop(grace=N)`` stops accepting new streams and
    waits up to N seconds for active ones to finish naturally. Active
    ext_proc streams end when Envoy closes them — there is no
    application-layer signal we can send into a WS tunnel from
    ``observability_mode: true``, so this is grace-then-cancel rather
    than coordinated drain.
    """
    if runtime is None:
        return
    logger.info(
        "gRPC drain starting: %d active streams, %ds grace",
        runtime.proc_servicer.active_stream_count,
        grace_seconds,
    )

    await runtime.server.stop(grace=grace_seconds)
    await runtime.publish_queue.stop(drain_timeout=min(5.0, float(grace_seconds)))

    try:
        await runtime.publish_service.state_service.close()
    except AttributeError:
        pass

    logger.info(
        "gRPC drain complete: published=%d queue_dropped=%d firehose_failed=%d",
        runtime.publish_queue.published_total,
        runtime.publish_queue.dropped_total,
        runtime.publish_queue.failed_total,
    )
