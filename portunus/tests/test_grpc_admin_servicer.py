"""Tests for the gRPC AdminService (replaces the FastAPI /cache/flush)."""

from unittest.mock import AsyncMock, MagicMock

import grpc
import pytest

from portunus.admin.v1 import admin_pb2
from portunus.exceptions import CacheError
from portunus.grpc.admin_servicer import PortunusAdminServicer
from portunus.grpc.proxy_auth import PROXY_KEY_HEADER

_PROXY_KEY = "test-proxy-key"


def _context(proxy_key: str | None) -> MagicMock:
    """A fake ServicerContext carrying (or omitting) the proxy key metadata."""
    ctx = MagicMock(spec=grpc.aio.ServicerContext)
    metadata = [(PROXY_KEY_HEADER, proxy_key)] if proxy_key is not None else []
    ctx.invocation_metadata.return_value = metadata
    # abort is awaitable and, like the real thing, terminates the RPC — model
    # it as raising so a test can assert the handler stopped there.
    ctx.abort = AsyncMock(side_effect=grpc.RpcError("aborted"))
    return ctx


def _servicer(flush_result=True, flush_exc=None) -> PortunusAdminServicer:
    cache_service = MagicMock()
    if flush_exc is not None:
        cache_service.flush_all = AsyncMock(side_effect=flush_exc)
    else:
        cache_service.flush_all = AsyncMock(return_value=flush_result)
    return PortunusAdminServicer(cache_service=cache_service, proxy_api_key=_PROXY_KEY)


@pytest.mark.asyncio
async def test_flush_cache_success():
    servicer = _servicer(flush_result=True)
    resp = await servicer.FlushCache(
        admin_pb2.FlushCacheRequest(), _context(_PROXY_KEY)
    )
    assert resp.success is True
    assert "flushed" in resp.message


@pytest.mark.asyncio
async def test_flush_cache_redis_unavailable_returns_success_false():
    servicer = _servicer(flush_result=False)
    resp = await servicer.FlushCache(
        admin_pb2.FlushCacheRequest(), _context(_PROXY_KEY)
    )
    assert resp.success is False
    assert "unavailable" in resp.message


@pytest.mark.asyncio
async def test_flush_cache_cache_error_returns_success_false():
    servicer = _servicer(flush_exc=CacheError("boom"))
    resp = await servicer.FlushCache(
        admin_pb2.FlushCacheRequest(), _context(_PROXY_KEY)
    )
    assert resp.success is False
    assert "failed" in resp.message


@pytest.mark.asyncio
async def test_flush_cache_rejects_wrong_proxy_key():
    servicer = _servicer()
    ctx = _context("wrong-key")
    with pytest.raises(grpc.RpcError):
        await servicer.FlushCache(admin_pb2.FlushCacheRequest(), ctx)
    ctx.abort.assert_awaited_once()
    assert ctx.abort.call_args.args[0] == grpc.StatusCode.UNAUTHENTICATED
    servicer._cache_service.flush_all.assert_not_called()


@pytest.mark.asyncio
async def test_flush_cache_rejects_missing_proxy_key():
    servicer = _servicer()
    ctx = _context(None)
    with pytest.raises(grpc.RpcError):
        await servicer.FlushCache(admin_pb2.FlushCacheRequest(), ctx)
    ctx.abort.assert_awaited_once()
    servicer._cache_service.flush_all.assert_not_called()
