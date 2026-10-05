"""Tests for the POST /cache/flush endpoint."""

from contextlib import AsyncExitStack
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus
from portunus.services.cache_service import CacheService


class FakeStateService:
    """Minimal StateService stand-in that hands out a (possibly None) redis client."""

    def __init__(self, client):
        self._client = client

    async def acquire_redis_connection(self):
        return self._client

    async def health_check(self):
        return self._client is not None


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def client_with_cache():
    async with AsyncExitStack() as stack:

        async def factory(state_service):
            cache = CacheService(state_service=state_service)
            stack.enter_context(patch("portunus.app.cache_service", cache))
            return await stack.enter_async_context(
                AsyncClient(
                    transport=ASGITransport(app=portunus),
                    base_url="http://test",
                    headers={"x-amzn-trace-id": "Root=test-trace-id"},
                )
            )

        yield factory


class TestCacheFlush:
    @pytest.mark.asyncio
    async def test_flush_success(self, client_with_cache, fake_redis):
        await fake_redis.set("auth:one", "cached")
        await fake_redis.set("auth:two", "cached")
        assert await fake_redis.dbsize() == 2

        http = await client_with_cache(FakeStateService(fake_redis))
        resp = await http.post("/cache/flush")

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert "flushed" in body["message"].lower()
        assert await fake_redis.dbsize() == 0

    @pytest.mark.asyncio
    async def test_flush_redis_unavailable(self, client_with_cache):
        http = await client_with_cache(FakeStateService(None))
        resp = await http.post("/cache/flush")

        assert resp.status_code == 503
        assert "unavailable" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_flush_redis_error(self, client_with_cache, fake_redis):
        fake_redis.flushdb = AsyncMock(side_effect=ConnectionError("connection reset"))

        http = await client_with_cache(FakeStateService(fake_redis))
        resp = await http.post("/cache/flush")

        assert resp.status_code == 500
        assert "failed" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_flush_returns_debug_id(self, client_with_cache, fake_redis):
        fake_redis.flushdb = AsyncMock(side_effect=ConnectionError("boom"))

        http = await client_with_cache(FakeStateService(fake_redis))
        resp = await http.post("/cache/flush")

        assert resp.status_code == 500
        assert resp.json()["debug_id"] == "test-trace-id"
