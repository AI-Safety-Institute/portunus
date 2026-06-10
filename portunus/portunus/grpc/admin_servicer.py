"""AdminService: operational actions over the in-task gRPC server.

Replaces the retired FastAPI ``POST /cache/flush`` endpoint. Served on the
same loopback gRPC server (127.0.0.1:9000) as ext_authz / ext_proc and gated
by the same ``x-portunus-proxy-key`` metadata — there is no separate auth
surface and no network-reachable admin port. See ``proto/portunus_admin``.
"""

from __future__ import annotations

import logging

import grpc
from portunus_admin.v1 import admin_pb2, admin_pb2_grpc

from portunus.exceptions import CacheError
from portunus.grpc.proxy_auth import extract_proxy_key, is_valid_proxy_key
from portunus.services.cache_service import CacheService

logger = logging.getLogger("api.grpc")


class PortunusAdminServicer(admin_pb2_grpc.AdminServiceServicer):
    """gRPC AdminService — operational actions (cache flush)."""

    def __init__(self, cache_service: CacheService, proxy_api_key: str) -> None:
        self._cache_service = cache_service
        self._proxy_api_key = proxy_api_key

    async def FlushCache(  # noqa: N802 — gRPC method name is fixed by the proto
        self,
        request: admin_pb2.FlushCacheRequest,
        context: grpc.aio.ServicerContext,
    ) -> admin_pb2.FlushCacheResponse:
        """Flush the entire Redis auth cache.

        Rejects with UNAUTHENTICATED if the proxy key is missing/wrong (same
        check the ext_authz / ext_proc services apply). Returns success=False
        rather than erroring when Redis is merely unreachable.
        """
        if not is_valid_proxy_key(extract_proxy_key(context), self._proxy_api_key):
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED, "invalid or missing proxy key"
            )

        try:
            flushed = await self._cache_service.flush_all()
        except CacheError as e:
            # flush_all raises CacheError on a Redis-side failure during flush.
            logger.error("Cache flush failed: %s", type(e).__name__)
            return admin_pb2.FlushCacheResponse(
                success=False, message=f"cache flush failed: {type(e).__name__}"
            )

        if flushed:
            logger.info("Auth cache flushed via AdminService.FlushCache")
            return admin_pb2.FlushCacheResponse(
                success=True, message="auth cache flushed"
            )
        return admin_pb2.FlushCacheResponse(
            success=False, message="cache backend unavailable"
        )
