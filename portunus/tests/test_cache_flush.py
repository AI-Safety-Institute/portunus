"""Tests for the POST /cache/flush endpoint."""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus
from portunus.exceptions import CacheError


@pytest.fixture
def mock_xray():
    """Mock X-Ray so it doesn't interfere with tests."""
    mock_segment = AsyncMock()
    mock_segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as mock:
        mock.recorder.current_segment.return_value = mock_segment
        yield mock


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=portunus)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestCacheFlush:
    @pytest.mark.asyncio
    async def test_flush_success(self, client, mock_xray):
        with patch("portunus.app.cache_service") as mock_cache:
            mock_cache.flush_all = AsyncMock(return_value=True)
            resp = await client.post("/cache/flush")

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert "flushed" in body["message"].lower()
        mock_cache.flush_all.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_flush_redis_unavailable(self, client, mock_xray):
        with patch("portunus.app.cache_service") as mock_cache:
            mock_cache.flush_all = AsyncMock(return_value=False)
            resp = await client.post("/cache/flush")

        assert resp.status_code == 503
        body = resp.json()
        assert "unavailable" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_flush_redis_error(self, client, mock_xray):
        with patch("portunus.app.cache_service") as mock_cache:
            mock_cache.flush_all = AsyncMock(side_effect=CacheError("connection reset"))
            resp = await client.post("/cache/flush")

        assert resp.status_code == 500
        body = resp.json()
        assert "failed" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_flush_returns_debug_id(self, client, mock_xray):
        with patch("portunus.app.cache_service") as mock_cache:
            mock_cache.flush_all = AsyncMock(side_effect=CacheError("boom"))
            resp = await client.post("/cache/flush")

        assert resp.status_code == 500
        assert resp.json()["debug_id"] == "test-trace-id"
