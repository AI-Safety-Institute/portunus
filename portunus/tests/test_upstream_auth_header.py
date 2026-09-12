"""Tests for the output_header/output_prefix fields on authorization results."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from portunus.app import AuthorizationResponse, portunus
from portunus.models import AuthPayload, AuthResult, PrincipalInfo
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.state_service import StateService

SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:test-api-key"


def _payload() -> str:
    """Base64 auth payload with placeholder credentials."""
    data = {
        "credentials": {
            "access_key_id": "AKIATEST",
            "secret_access_key": "SECRETTEST",
            "session_token": "TESTTOKEN",
        },
        "secret_arn": SECRET_ARN,
    }
    return base64.b64encode(json.dumps(data).encode()).decode()


def _auth_result(
    output_header: str | None = None, output_prefix: str | None = None
) -> AuthResult:
    return AuthResult(
        api_key="sk-test-key",
        signing_key=None,
        principal_info=PrincipalInfo(
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/session",
            account_id="123456789012",
        ),
        output_header=output_header,
        output_prefix=output_prefix,
    )


AUTHORISE_BODY = {
    "payload": _payload(),
    "target_host": "api.example.com",
    "signable_request": {
        "type": "anthropic",
        "content_digest": "sha-256=:abc:",
        "content_type": "application/json",
        "method": "POST",
        "url": "https://api.example.com/v1/messages",
    },
}


class TestAuthorizationResponseModel:
    def test_output_fields_default_to_none(self):
        response = AuthorizationResponse(api_key="sk", request_id="req")

        assert response.output_header is None
        assert response.output_prefix is None
        assert response.model_dump()["output_header"] is None

    def test_output_fields_round_trip(self):
        response = AuthorizationResponse.model_validate(
            {
                "api_key": "sk",
                "request_id": "req",
                "output_header": "x-goog-api-key",
                "output_prefix": "",
            }
        )

        assert response.output_header == "x-goog-api-key"
        assert response.output_prefix == ""

    def test_empty_output_header_is_rejected(self):
        with pytest.raises(ValidationError):
            AuthorizationResponse(api_key="sk", request_id="req", output_header="")


class TestAuthResultOutputFields:
    def test_defaults_to_none(self):
        result = _auth_result()

        assert result.output_header is None
        assert result.output_prefix is None

    def test_from_dict_reads_output_fields(self):
        data = _auth_result(
            output_header="authorization", output_prefix="Bearer "
        ).to_dict()

        result = AuthResult.from_dict(data)

        assert result.output_header == "authorization"
        assert result.output_prefix == "Bearer "

    def test_from_dict_without_output_fields(self):
        data = _auth_result().to_dict()
        del data["output_header"]
        del data["output_prefix"]

        result = AuthResult.from_dict(data)

        assert result.output_header is None
        assert result.output_prefix is None


def _cache_backed_by(client: fakeredis.aioredis.FakeRedis) -> CacheService:
    state_service = MagicMock(spec=StateService)
    state_service.acquire_redis_connection = AsyncMock(return_value=client)
    return CacheService(state_service=state_service)


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


class TestCacheRoundTrip:
    @pytest.mark.asyncio
    async def test_output_fields_survive_the_cache(self, fake_redis):
        """A cache hit returns the same output fields as the original result."""
        cache = _cache_backed_by(fake_redis)
        stored = _auth_result(output_header="x-goog-api-key", output_prefix="")

        assert await cache.cache_auth_result("payload", stored, ttl_seconds=60)
        cached = await cache.get_cached_auth_result("payload")

        assert cached is not None
        assert cached.output_header == "x-goog-api-key"
        assert cached.output_prefix == ""
        assert cached.api_key == stored.api_key

    @pytest.mark.asyncio
    async def test_entry_without_output_fields_loads_as_none(self, fake_redis):
        """Entries written before the fields existed still load."""
        cache = _cache_backed_by(fake_redis)
        legacy = {
            "api_key": "sk-legacy",
            "principal_info": _auth_result().principal_info.to_dict(),
            "signing_key": None,
        }
        await fake_redis.set(cache.generate_cache_key("payload"), json.dumps(legacy))

        cached = await cache.get_cached_auth_result("payload")

        assert cached is not None
        assert cached.api_key == "sk-legacy"
        assert cached.output_header is None
        assert cached.output_prefix is None


class TestAuthenticateCacheHit:
    @pytest.mark.asyncio
    async def test_cached_result_is_returned_unchanged(self):
        """authenticate() must not rebuild a cached result and drop fields."""
        cached = _auth_result(output_header="x-goog-api-key", output_prefix="")
        cache_service = MagicMock()
        cache_service.get_cached_auth_result = AsyncMock(return_value=cached)
        service = AuthService(
            secrets_service=MagicMock(boto_session=MagicMock()),
            cache_service=cache_service,
            validation_service=MagicMock(),
        )

        result = await service.authenticate(
            AuthPayload.from_contents(_payload()), "req"
        )

        assert result is cached


@pytest.fixture
def mock_xray():
    mock_segment = AsyncMock()
    mock_segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as mock:
        mock.recorder.current_segment.return_value = mock_segment
        yield mock


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=portunus), base_url="http://test"
    ) as http_client:
        yield http_client


class TestAuthoriseEndpoint:
    @pytest.mark.asyncio
    async def test_static_key_omits_output_fields(self, client, mock_xray):
        """Existing static-key results produce null output fields."""
        with (
            patch("portunus.app.auth_service") as auth_service,
            patch("portunus.app.publish_service") as publish_service,
        ):
            auth_service.authenticate = AsyncMock(return_value=_auth_result())
            publish_service.publish_metadata = AsyncMock()

            response = await client.post("/authorise", json=AUTHORISE_BODY)

        assert response.status_code == 200
        body = response.json()
        assert body["api_key"] == "sk-test-key"
        assert body["output_header"] is None
        assert body["output_prefix"] is None

    @pytest.mark.asyncio
    async def test_output_fields_pass_through(self, client, mock_xray):
        """output_header/output_prefix on the auth result reach the response."""
        auth_result = _auth_result(output_header="x-goog-api-key", output_prefix="")
        with (
            patch("portunus.app.auth_service") as auth_service,
            patch("portunus.app.publish_service") as publish_service,
        ):
            auth_service.authenticate = AsyncMock(return_value=auth_result)
            publish_service.publish_metadata = AsyncMock()

            response = await client.post("/authorise", json=AUTHORISE_BODY)

        assert response.status_code == 200
        body = response.json()
        assert body["output_header"] == "x-goog-api-key"
        assert body["output_prefix"] == ""
