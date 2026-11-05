"""Tests for keying cached authorisation results on payload and target host.

``auth_cache_key`` is the one definition of the key, shared by the Redis cache
(``CacheService.generate_cache_key``) and any in-process tier in front of it.
Its value is pinned to the formula Portunus has always used, so a deploy does
not invalidate every Redis entry.
"""

import hashlib
import json
from typing import Optional
from unittest.mock import MagicMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from portunus.exceptions import AuthenticationError
from portunus.models import AuthResult, PrincipalInfo, SecretsManagerAuthPayload
from portunus.services.cache_service import CacheService, auth_cache_key
from portunus.services.secret_validation_service import SecretValidationService
from portunus.services.state_service import StateService


def validated_api_key(secret: str, target_host: Optional[str]) -> str:
    """The api_key the miss-path validator admits for ``target_host``."""
    result = SecretValidationService().validate_secret(secret, target_host)
    assert isinstance(result, SecretsManagerAuthPayload)
    return result.api_key


@pytest.fixture
def cache() -> CacheService:
    return CacheService(state_service=MagicMock(spec=StateService))


class TestGenerateCacheKey:
    def test_golden_key_for_a_known_input(self, cache):
        """A literal pinned value, so a formula change cannot pass by construction."""
        assert (
            cache.generate_cache_key("payload", "api.example.com")
            == hashlib.sha256(b"payload\napi.example.com").hexdigest()
            == "eb1c07e27c4ed0b2e6ef343d74273a5a5b15e2f3dc1b3e8a21b389ab05a06a1f"
        )

    @pytest.mark.parametrize(
        ("payload", "target_host"),
        [
            ("payload", "api.example.com"),
            ("payload", "api.other.example"),
            ("payload", None),
            ("payload", ""),
            ("", "api.example.com"),
            ('{"credentials": {"access_key_id": "AKIA"}}', "API.Example.com:443"),
        ],
    )
    def test_key_is_byte_identical_to_the_historical_formula(
        self, cache, payload, target_host
    ):
        """The key must not change value: a new format would cold-start Redis.

        Every task in a rolling deploy shares one Redis, so a different key
        formula means every entry misses once and the roll pays a burst of
        full authentications (STS + Secrets Manager). This pins the formula
        Portunus has used since the key was introduced.
        """
        expected = hashlib.sha256(
            f"{payload}\n{target_host or ''}".encode("utf-8")
        ).hexdigest()

        assert auth_cache_key(payload, target_host) == expected
        assert cache.generate_cache_key(payload, target_host) == expected

    def test_service_method_delegates_to_the_shared_function(self, cache):
        """Redis and any in-process tier must key on the same function."""
        assert cache.generate_cache_key("payload", "api.example.com") == auth_cache_key(
            "payload", "api.example.com"
        )

    def test_host_scoping_still_distinguishes(self, cache):
        payload = "payload-xyz"
        key_a = cache.generate_cache_key(payload, "api.openai.com")
        key_b = cache.generate_cache_key(payload, "api.anthropic.com")
        key_none = cache.generate_cache_key(payload, None)
        assert len({key_a, key_b, key_none}) == 3

    def test_none_and_empty_host_share_the_unrestricted_entry(self, cache):
        payload = "payload-xyz"
        assert cache.generate_cache_key(payload, None) == cache.generate_cache_key(
            payload, ""
        )


class TestHostRestrictionRecheckStaysFailClosed:
    """The miss-path host check is an exact comparison and fails closed."""

    SECRET = json.dumps({"secret": "sk-real", "host": "api.anthropic.com"})

    def test_exact_host_passes(self):
        assert validated_api_key(self.SECRET, "api.anthropic.com") == "sk-real"

    @pytest.mark.parametrize(
        "bad_host",
        ["evil.example.com", "api.anthropic.com.evil.com", "api.anthropic.com:8443"],
    )
    def test_other_host_fails_closed(self, bad_host):
        with pytest.raises(AuthenticationError):
            validated_api_key(self.SECRET, bad_host)

    def test_missing_target_host_fails_closed(self):
        with pytest.raises(AuthenticationError):
            validated_api_key(self.SECRET, None)


def _cache_backed_by(client: fakeredis.aioredis.FakeRedis) -> CacheService:
    async def execute_redis(operation):
        return await operation(client)

    state_service = MagicMock(spec=StateService)
    state_service.execute_redis = execute_redis
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
    async def test_upstream_header_fields_round_trip(self, fake_redis):
        cache = _cache_backed_by(fake_redis)
        result = _result()
        result.output_header = "x-goog-api-key"
        result.output_prefix = ""

        await cache.cache_auth_result("payload", "api.example.com", result, 60)

        cached = await cache.get_cached_auth_result("payload", "api.example.com")
        assert cached is not None
        assert cached.output_header == "x-goog-api-key"
        assert cached.output_prefix == ""
