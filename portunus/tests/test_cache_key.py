"""Tests for keying cached authorisation results on payload and target host."""

import hashlib
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from portunus.models import AuthResult, PrincipalInfo
from portunus.services.cache_service import CacheService
from portunus.services.state_service import StateService


def _cache_backed_by(client: fakeredis.aioredis.FakeRedis) -> CacheService:
    state_service = MagicMock(spec=StateService)
    state_service.acquire_redis_connection = AsyncMock(return_value=client)
    return CacheService(state_service=state_service)


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def _result(api_key: str = "sk-example") -> AuthResult:
    return AuthResult(
        api_key=api_key,
        principal_info=PrincipalInfo(
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/session",
            account_id="123456789012",
        ),
    )


class TestGenerateCacheKey:
    def setup_method(self):
        self.cache = CacheService(state_service=MagicMock(spec=StateService))

    def test_hashes_the_payload_and_the_target_host(self):
        key = self.cache.generate_cache_key("payload", "api.example.com")

        assert key == hashlib.sha256(b"payload\napi.example.com").hexdigest()

    def test_same_payload_different_targets_yield_different_keys(self):
        example = self.cache.generate_cache_key("payload", "api.example.com")
        other = self.cache.generate_cache_key("payload", "api.other.example")

        assert example != other

    def test_no_target_keys_apart_from_a_named_target(self):
        untargeted = self.cache.generate_cache_key("payload", None)
        example = self.cache.generate_cache_key("payload", "api.example.com")

        assert untargeted != example


class TestCacheIsKeyedByTarget:
    @pytest.mark.asyncio
    async def test_hit_for_one_target_is_a_miss_for_another(self, fake_redis):
        cache = _cache_backed_by(fake_redis)

        assert await cache.cache_auth_result(
            "payload", "api.example.com", _result(), 60
        )

        cached = await cache.get_cached_auth_result("payload", "api.example.com")
        assert cached is not None
        assert cached.api_key == "sk-example"
        assert (
            await cache.get_cached_auth_result("payload", "api.other.example") is None
        )
        assert await cache.get_cached_auth_result("payload", None) is None

    @pytest.mark.asyncio
    async def test_entries_for_two_targets_coexist(self, fake_redis):
        cache = _cache_backed_by(fake_redis)

        await cache.cache_auth_result("payload", "api.example.com", _result("sk-a"), 60)
        await cache.cache_auth_result(
            "payload", "api.other.example", _result("sk-b"), 60
        )

        example = await cache.get_cached_auth_result("payload", "api.example.com")
        other = await cache.get_cached_auth_result("payload", "api.other.example")
        assert example is not None and example.api_key == "sk-a"
        assert other is not None and other.api_key == "sk-b"

    @pytest.mark.asyncio
    async def test_invalidation_is_per_target(self, fake_redis):
        cache = _cache_backed_by(fake_redis)
        await cache.cache_auth_result("payload", "api.example.com", _result(), 60)
        await cache.cache_auth_result("payload", "api.other.example", _result(), 60)

        assert await cache.invalidate_cache_entry("payload", "api.example.com")

        assert await cache.get_cached_auth_result("payload", "api.example.com") is None
        assert (
            await cache.get_cached_auth_result("payload", "api.other.example")
            is not None
        )
