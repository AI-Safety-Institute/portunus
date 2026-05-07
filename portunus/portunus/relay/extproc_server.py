"""Lifecycle bootstrap for the ext_proc gRPC server.

Runs alongside the FastAPI/uvicorn HTTP server on the same asyncio event loop,
so the ExternalProcessor handler can call PublishService in-process.
"""

from __future__ import annotations

import logging

import grpc
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as ep_grpc

from portunus.relay.extproc import ExtProcRelayServicer
from portunus.services.publish_service import PublishService

logger = logging.getLogger("api.access")


_GRPC_OPTIONS = [
    ("grpc.keepalive_time_ms", 30_000),
    ("grpc.keepalive_timeout_ms", 10_000),
    ("grpc.http2.max_pings_without_data", 0),
]


async def start_extproc_server(
    publish_service: PublishService, port: int
) -> grpc.aio.Server:
    """Start the ext_proc gRPC server. Caller is responsible for shutdown."""
    server = grpc.aio.server(options=_GRPC_OPTIONS)
    ep_grpc.add_ExternalProcessorServicer_to_server(
        ExtProcRelayServicer(publish_service=publish_service), server
    )
    server.add_insecure_port(f"0.0.0.0:{port}")
    await server.start()
    logger.info(f"ext_proc gRPC server listening on :{port}")
    return server


async def stop_extproc_server(
    server: grpc.aio.Server, grace_seconds: float = 5.0
) -> None:
    await server.stop(grace=grace_seconds)
    logger.info("ext_proc gRPC server stopped")
