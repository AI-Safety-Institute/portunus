"""Main FastAPI application for Portunus.

The FastAPI surface hosts the admin endpoints:

- ``GET /ping`` — health check for ECS / ALB readiness.
- ``POST /cache/flush`` — operator cache invalidation.

Customer-facing auth and observability run on the gRPC server in
:mod:`portunus.grpc` as Envoy ext_authz / ext_proc filters; WebSockets
flow through Envoy directly to upstream with ext_proc observing frames.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request, Response
from pydantic import BaseModel

from portunus.config import config
from portunus.logging import LoggingMiddleware
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.publish_service import PublishService
from portunus.services.state_service import StateService
from portunus.services.xray_service import XRayService
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")

# Initialize services
state_service = StateService()
cache_service = CacheService(state_service=state_service)
publish_service = PublishService(state_service=state_service)
auth_service = AuthService(cache_service=cache_service)
xray_service = XRayService()

common_router = APIRouter()
portunus_router = APIRouter()


class ErrorResponse(BaseModel):
    """Error response model.

    Attributes:
        message: Error message describing what went wrong
        debug_id: Debug/trace ID for correlation and troubleshooting
    """

    message: str
    debug_id: str


class CacheFlushResponse(BaseModel):
    """Response model for cache flush operations.

    Attributes:
        message: Status message
        success: Whether the flush succeeded
    """

    message: str
    success: bool


@portunus_router.post("/cache/flush")
async def flush_cache(
    response: Response,
) -> CacheFlushResponse | ErrorResponse:
    """Flush the entire auth cache.

    Removes all cached authentication responses from Redis, forcing
    subsequent requests to re-authenticate via AWS. Used when a cached
    API key may have been compromised.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Cache flush requested, trace_id: {trace_id}")

    try:
        success = await cache_service.flush_all()
        if success:
            logger.info(f"Cache flush completed successfully, trace_id: {trace_id}")
            return CacheFlushResponse(
                message="Auth cache flushed successfully",
                success=True,
            )
        else:
            response.status_code = 503
            return ErrorResponse(
                message="Redis unavailable for cache flush",
                debug_id=trace_id,
            )
    except Exception as e:
        logger.error(f"Cache flush failed: {e}, trace_id: {trace_id}")
        response.status_code = 500
        return ErrorResponse(
            message="Failed to flush cache",
            debug_id=trace_id,
        )


@common_router.get("/ping")
async def ping(request: Request) -> dict:
    """Health-check endpoint.

    Returns the overall service status, Redis connectivity, and a
    server-side timestamp.
    """
    redis_health = "OK" if await state_service.health_check() else "FAIL"
    return {
        "status": "healthy",
        "redis": redis_health,
        "timestamp": generate_iso_timestamp(),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle.

    Starts the gRPC server (if enabled) on startup; tears it down,
    drains active streams, and closes Redis on shutdown.
    """
    from portunus.grpc.server import start_grpc_server, stop_grpc_server

    grpc_runtime = await start_grpc_server(
        config=config.grpc,
        auth_service=auth_service,
        publish_service=publish_service,
    )

    yield

    await stop_grpc_server(
        grpc_runtime, grace_seconds=config.grpc.graceful_shutdown_seconds
    )

    logger.info("Shutting down Redis connections")
    await state_service.close_redis_client()
    logger.info("Redis connections closed")


portunus = FastAPI(title="Portunus", lifespan=lifespan)
portunus.add_middleware(LoggingMiddleware)
portunus.include_router(portunus_router)
portunus.include_router(common_router)
