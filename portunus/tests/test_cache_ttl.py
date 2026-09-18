"""Tests for cache TTL derivation and the expires_at round trip."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from portunus.models import AuthResult, PrincipalInfo
from portunus.services.cache_service import (
    TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS,
    CacheService,
    effective_cache_ttl,
)
from portunus.services.state_service import StateService

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


class TestEffectiveCacheTtl:
    def test_cache_duration_caps_a_long_lived_token(self):
        ttl = effective_cache_ttl(
            cache_duration=3600, token_expires_at=NOW + timedelta(days=1), now=NOW
        )

        assert ttl == 3600

    def test_token_expiry_less_margin_caps_the_ttl(self):
        ttl = effective_cache_ttl(
            cache_duration=86400,
            token_expires_at=NOW + timedelta(seconds=3600),
            now=NOW,
        )

        assert ttl == 3600 - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS

    def test_token_inside_the_safety_margin_is_not_cached(self):
        ttl = effective_cache_ttl(
            cache_duration=86400, token_expires_at=NOW + timedelta(seconds=30), now=NOW
        )

        assert ttl == 0

    def test_never_negative(self):
        ttl = effective_cache_ttl(
            cache_duration=86400, token_expires_at=NOW - timedelta(seconds=1), now=NOW
        )

        assert ttl == 0


def _cache_backed_by(client: fakeredis.aioredis.FakeRedis) -> CacheService:
    state_service = MagicMock(spec=StateService)
    state_service.acquire_redis_connection = AsyncMock(return_value=client)
    return CacheService(state_service=state_service)


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def _minted_result() -> AuthResult:
    return AuthResult(
        api_key="sk-ant-oat01-example",
        signing_key=None,
        principal_info=PrincipalInfo(
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/session",
            account_id="123456789012",
        ),
        output_header="authorization",
        output_prefix="Bearer ",
        expires_at=NOW + timedelta(hours=1),
    )


class TestExpiresAtRoundTrips:
    @pytest.mark.asyncio
    async def test_expires_at_survives_the_cache(self, fake_redis):
        cache = _cache_backed_by(fake_redis)

        assert await cache.cache_auth_result("payload", _minted_result(), 60)
        cached = await cache.get_cached_auth_result("payload")

        assert cached is not None
        assert cached.expires_at == NOW + timedelta(hours=1)

    @pytest.mark.asyncio
    async def test_entry_without_expires_at_loads_as_none(self, fake_redis):
        cache = _cache_backed_by(fake_redis)
        legacy = {
            "api_key": "sk-legacy",
            "principal_info": _minted_result().principal_info.to_dict(),
            "signing_key": None,
        }
        await fake_redis.set(cache.generate_cache_key("payload"), json.dumps(legacy))

        cached = await cache.get_cached_auth_result("payload")

        assert cached is not None
        assert cached.expires_at is None

    def test_auth_result_dict_round_trip(self):
        data = _minted_result().to_dict()

        assert data["expires_at"] == "2026-01-01T13:00:00+00:00"
        assert AuthResult.from_dict(data) == _minted_result()
