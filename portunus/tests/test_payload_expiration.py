"""Tests for the credential expiration carried by the auth payload."""

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from portunus.models import AuthPayload
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.payload_service import encode_payload
from portunus.services.state_service import StateService

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:test-api-key"
CALLER_ARN = "arn:aws:sts::123456789012:assumed-role/TestRole/session"


def _raw_payload(data: dict) -> str:
    return base64.b64encode(json.dumps(data).encode()).decode()


def _encoded_payload(expires_in: timedelta) -> str:
    """A payload as ``encode_payload`` (and the CLI) produce it."""
    return encode_payload(
        {
            "AccessKeyId": "AKIATEST",
            "SecretAccessKey": "SECRETTEST",
            "SessionToken": "TESTTOKEN",
            "Expiration": datetime.now(timezone.utc) + expires_in,
        },
        SECRET_ARN,
    )


class TestPayloadCredentialExpiration:
    def test_top_level_expiration_from_encode_payload_is_parsed(self):
        payload = AuthPayload.from_contents(_encoded_payload(timedelta(hours=12)))

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

    def test_to_dict_without_expiration_writes_none(self):
        raw = _raw_payload(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRETTEST",
                },
                "secret_arn": SECRET_ARN,
            }
        )

        data = AuthPayload.from_contents(raw).to_dict()

        assert data["expiration"] is None
        assert data["credentials"]["expiration"] is None


def _cache_backed_by(client: fakeredis.aioredis.FakeRedis) -> CacheService:
    state_service = MagicMock(spec=StateService)
    state_service.acquire_redis_connection = AsyncMock(return_value=client)
    return CacheService(state_service=state_service)


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def _service_for(raw_secret: str, cache: CacheService) -> AuthService:
    """An AuthService whose STS identity and secret fetch are canned."""
    sts_client = AsyncMock()
    sts_client.get_caller_identity = AsyncMock(return_value={"Arn": CALLER_ARN})
    sts_client.__aenter__ = AsyncMock(return_value=sts_client)
    sts_client.__aexit__ = AsyncMock(return_value=None)
    boto_session = MagicMock()
    boto_session.create_client = MagicMock(return_value=sts_client)
    secrets_service = MagicMock(boto_session=boto_session)
    secrets_service.fetch_secret = AsyncMock(return_value=raw_secret)
    return AuthService(secrets_service=secrets_service, cache_service=cache)


class TestStoredKeyCacheTtl:
    @pytest.mark.asyncio
    async def test_stored_key_is_cached_for_the_cache_duration(self, fake_redis):
        """Reading the expiration must not shorten how long a stored key is cached."""
        cache = _cache_backed_by(fake_redis)
        service = _service_for("sk-static", cache)
        payload = AuthPayload.from_contents(_encoded_payload(timedelta(hours=1)))
        assert payload.credentials.seconds_until_expiration() is not None

        result = await service.authenticate(payload, "req", "api.example.com")

        assert result.api_key == "sk-static"
        ttl = await fake_redis.ttl(cache.generate_cache_key(payload.raw))
        assert cache.cache_duration > 3600
        assert cache.cache_duration - 5 < ttl <= cache.cache_duration
