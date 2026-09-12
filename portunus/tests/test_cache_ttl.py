"""Tests for cache TTL derivation and credential expiration parsing."""

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from portunus.models import AuthPayload, AuthResult, PrincipalInfo
from portunus.services.cache_service import (
    TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS,
    CacheService,
    effective_cache_ttl,
)
from portunus.services.payload_service import encode_payload
from portunus.services.state_service import StateService

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:test-api-key"


class TestEffectiveCacheTtl:
    def test_defaults_to_cache_duration(self):
        ttl = effective_cache_ttl(
            cache_duration=3600, credential_expiry_seconds=None, token_expires_at=None
        )

        assert ttl == 3600

    def test_credential_expiry_caps_the_ttl(self):
        ttl = effective_cache_ttl(
            cache_duration=3600, credential_expiry_seconds=600, token_expires_at=None
        )

        assert ttl == 600

    def test_cache_duration_caps_long_lived_credentials(self):
        ttl = effective_cache_ttl(
            cache_duration=3600,
            credential_expiry_seconds=43200,
            token_expires_at=None,
        )

        assert ttl == 3600

    def test_token_expiry_less_margin_caps_the_ttl(self):
        ttl = effective_cache_ttl(
            cache_duration=86400,
            credential_expiry_seconds=43200,
            token_expires_at=NOW + timedelta(seconds=3600),
            now=NOW,
        )

        assert ttl == 3600 - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS

    def test_credential_expiry_wins_over_a_longer_lived_token(self):
        ttl = effective_cache_ttl(
            cache_duration=86400,
            credential_expiry_seconds=120,
            token_expires_at=NOW + timedelta(seconds=3600),
            now=NOW,
        )

        assert ttl == 120

    def test_token_inside_the_safety_margin_is_not_cached(self):
        ttl = effective_cache_ttl(
            cache_duration=86400,
            credential_expiry_seconds=None,
            token_expires_at=NOW + timedelta(seconds=200),
            now=NOW,
        )

        assert ttl == 0

    def test_never_negative(self):
        ttl = effective_cache_ttl(
            cache_duration=86400,
            credential_expiry_seconds=None,
            token_expires_at=NOW - timedelta(seconds=1),
            now=NOW,
        )

        assert ttl == 0


def _raw_payload(data: dict) -> str:
    return base64.b64encode(json.dumps(data).encode()).decode()


class TestPayloadCredentialExpiration:
    def test_top_level_expiration_from_encode_payload_is_parsed(self):
        expiration = datetime.now(timezone.utc) + timedelta(hours=12)
        raw = encode_payload(
            {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "SECRETTEST",
                "SessionToken": "TESTTOKEN",
                "Expiration": expiration,
            },
            SECRET_ARN,
        )

        payload = AuthPayload.from_contents(raw)

        assert payload.credentials.expiration == expiration
        remaining = payload.credentials.seconds_until_expiration()
        assert remaining is not None
        assert 12 * 3600 - 5 < remaining <= 12 * 3600

    def test_expiration_inside_credentials_is_parsed(self):
        raw = _raw_payload(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRETTEST",
                    "session_token": "TESTTOKEN",
                    "expiration": "2026-01-01T13:00:00Z",
                },
                "secret_arn": SECRET_ARN,
            }
        )

        payload = AuthPayload.from_contents(raw)

        assert payload.credentials.expiration == NOW + timedelta(hours=1)

    def test_nested_expiration_takes_precedence(self):
        raw = _raw_payload(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRETTEST",
                    "expiration": "2026-01-01T13:00:00Z",
                },
                "expiration": "2026-01-01T14:00:00Z",
                "secret_arn": SECRET_ARN,
            }
        )

        payload = AuthPayload.from_contents(raw)

        assert payload.credentials.expiration == NOW + timedelta(hours=1)

    def test_payload_without_expiration_has_none(self):
        raw = _raw_payload(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRETTEST",
                },
                "secret_arn": SECRET_ARN,
            }
        )

        payload = AuthPayload.from_contents(raw)

        assert payload.credentials.expiration is None
        assert payload.credentials.seconds_until_expiration() is None

    def test_to_dict_round_trips_the_expiration(self):
        raw = _raw_payload(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRETTEST",
                },
                "expiration": "2026-01-01T14:00:00+00:00",
                "secret_arn": SECRET_ARN,
            }
        )

        data = AuthPayload.from_contents(raw).to_dict()

        assert data["expiration"] == "2026-01-01T14:00:00+00:00"
        assert data["credentials"]["expiration"] == "2026-01-01T14:00:00+00:00"


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
