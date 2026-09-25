"""Tests for the authentication service, including credential error handling."""

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
import pytest_asyncio
import redis.exceptions
from botocore.exceptions import ClientError

from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    UpstreamServiceError,
)
from portunus.models import (
    AnthropicWifSecret,
    AuthPayload,
    AuthResult,
    AwsCredentials,
    PrincipalInfo,
    SecretsManagerAuthPayload,
)
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import (
    TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS,
    CacheService,
)
from portunus.services.federation_service import MintedToken
from portunus.services.state_service import StateService


@pytest.fixture
def auth_service():
    """Create an AuthService instance with mocked dependencies."""
    mock_secrets_service = MagicMock()
    mock_secrets_service.boto_session = MagicMock()
    mock_cache_service = MagicMock()
    mock_cache_service.get_cached_auth_result = AsyncMock(return_value=None)
    mock_cache_service.cache_auth_result = AsyncMock(return_value=True)
    mock_validation_service = MagicMock()

    return AuthService(
        secrets_service=mock_secrets_service,
        cache_service=mock_cache_service,
        validation_service=mock_validation_service,
    )


@pytest.fixture
def valid_credentials():
    """Create valid AWS credentials for testing."""
    return AwsCredentials(
        access_key_id="AKIATEST123",
        secret_access_key="secretkey123",
        session_token="sessiontoken123",
    )


@pytest.fixture
def payload(valid_credentials):
    """Create an AuthPayload with a raw value so the cache path is exercised."""
    return AuthPayload(
        raw="raw-payload",
        credentials=valid_credentials,
        secret_arn="arn:aws:secretsmanager:eu-west-2:123456789012:secret:test",
    )


PRINCIPAL_ARN = "arn:aws:sts::123456789012:assumed-role/TestRole/session"


def install_sts_client(auth_service, arn=PRINCIPAL_ARN):
    """Point auth_service at a mock STS client whose caller identity is arn."""
    mock_sts_client = AsyncMock()
    mock_sts_client.get_caller_identity = AsyncMock(return_value={"Arn": arn})
    mock_sts_client.__aenter__ = AsyncMock(return_value=mock_sts_client)
    mock_sts_client.__aexit__ = AsyncMock(return_value=None)
    auth_service.boto_session.create_client = MagicMock(return_value=mock_sts_client)


def test_default_mint_service_shares_the_secrets_boto_session(auth_service):
    assert (
        auth_service.mint_service.sts.boto_session
        is auth_service.secrets_service.boto_session
    )


class TestGetAwsIdentity:
    """Tests for the get_aws_identity method."""

    @pytest.mark.asyncio
    async def test_expired_token_raises_credentials_error(
        self, auth_service, valid_credentials
    ):
        """Test that ExpiredToken from STS raises CredentialsError."""
        mock_sts_client = AsyncMock()
        mock_sts_client.get_caller_identity = AsyncMock(
            side_effect=ClientError(
                error_response={
                    "Error": {"Code": "ExpiredToken", "Message": "Token has expired"}
                },
                operation_name="GetCallerIdentity",
            )
        )
        mock_sts_client.__aenter__ = AsyncMock(return_value=mock_sts_client)
        mock_sts_client.__aexit__ = AsyncMock(return_value=None)

        auth_service.boto_session.create_client = MagicMock(
            return_value=mock_sts_client
        )

        with pytest.raises(CredentialsError) as exc_info:
            await auth_service.get_aws_identity(valid_credentials)

        assert "expired" in str(exc_info.value.message).lower()

    @pytest.mark.asyncio
    async def test_other_client_error_raises_credentials_error(
        self, auth_service, valid_credentials
    ):
        """Test that other ClientErrors raise CredentialsError."""
        mock_sts_client = AsyncMock()
        mock_sts_client.get_caller_identity = AsyncMock(
            side_effect=ClientError(
                error_response={
                    "Error": {
                        "Code": "InvalidIdentityToken",
                        "Message": "Token is invalid",
                    }
                },
                operation_name="GetCallerIdentity",
            )
        )
        mock_sts_client.__aenter__ = AsyncMock(return_value=mock_sts_client)
        mock_sts_client.__aexit__ = AsyncMock(return_value=None)

        auth_service.boto_session.create_client = MagicMock(
            return_value=mock_sts_client
        )

        with pytest.raises(CredentialsError) as exc_info:
            await auth_service.get_aws_identity(valid_credentials)

        assert "Failed to get caller identity" in str(exc_info.value.message)

    @pytest.mark.asyncio
    async def test_invalid_credentials_raises_credentials_error(self, auth_service):
        """Test that credentials failing is_valid() raise CredentialsError."""
        invalid_credentials = MagicMock(spec=AwsCredentials)
        invalid_credentials.is_valid.return_value = False

        with pytest.raises(CredentialsError):
            await auth_service.get_aws_identity(invalid_credentials)

    @pytest.mark.asyncio
    async def test_none_credentials_raises_credentials_error(self, auth_service):
        """Test that None credentials raise CredentialsError."""
        with pytest.raises(CredentialsError):
            await auth_service.get_aws_identity(None)


class TestAuthenticateCacheRead:
    """Tests for how authenticate handles the cache read."""

    @pytest.mark.asyncio
    async def test_cache_hit_short_circuits(self, auth_service, payload):
        """A cache hit returns the cached result without calling AWS."""
        auth_service.cache_service.get_cached_auth_result.return_value = AuthResult(
            api_key="sk-cached",
            principal_info=PrincipalInfo(arn=PRINCIPAL_ARN, account_id="123456789012"),
        )
        auth_service.boto_session.create_client = MagicMock()
        auth_service.secrets_service.fetch_secret = AsyncMock()

        result = await auth_service.authenticate(payload, "req-id")

        assert result.api_key == "sk-cached"
        auth_service.boto_session.create_client.assert_not_called()
        auth_service.secrets_service.fetch_secret.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "error",
        [TimeoutError(), redis.exceptions.TimeoutError("Timeout reading from socket")],
        ids=["builtin", "redis"],
    )
    async def test_cache_timeout_rejects_without_full_auth(
        self, auth_service, payload, error
    ):
        """A cache-read timeout raises TimeoutError and never falls back to AWS."""
        auth_service.cache_service.get_cached_auth_result.side_effect = error
        auth_service.boto_session.create_client = MagicMock()
        auth_service.secrets_service.fetch_secret = AsyncMock()

        with pytest.raises(TimeoutError) as exc_info:
            await auth_service.authenticate(payload, "req-id")

        assert type(exc_info.value) is TimeoutError
        auth_service.boto_session.create_client.assert_not_called()
        auth_service.secrets_service.fetch_secret.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_connection_error_falls_back_to_full_auth(
        self, auth_service, payload
    ):
        """Redis being unreachable still degrades to the full STS + secret path."""
        auth_service.cache_service.get_cached_auth_result.side_effect = (
            redis.exceptions.ConnectionError("Connection refused")
        )
        install_sts_client(auth_service)
        auth_service.secrets_service.fetch_secret = AsyncMock(
            return_value='{"api_key": "sk-live"}'
        )
        auth_service.validation_service.validate_secret.return_value = (
            SecretsManagerAuthPayload(secret="sk-live")
        )

        result = await auth_service.authenticate(payload, "req-id")

        assert result.api_key == "sk-live"
        assert result.principal_info.arn == PRINCIPAL_ARN
        auth_service.boto_session.create_client.assert_called_once()
        auth_service.secrets_service.fetch_secret.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    async def test_redis_timeout_propagates_through_real_cache_service(self, payload):
        """CacheService must not wrap a Redis timeout in CacheError."""
        redis_client = MagicMock()
        redis_client.get = AsyncMock(
            side_effect=redis.exceptions.TimeoutError("Timeout reading from socket")
        )
        state_service = MagicMock()
        state_service.acquire_redis_connection = AsyncMock(return_value=redis_client)
        secrets_service = MagicMock()
        secrets_service.boto_session = MagicMock()
        secrets_service.fetch_secret = AsyncMock()
        service = AuthService(
            secrets_service=secrets_service,
            cache_service=CacheService(state_service=state_service),
            validation_service=MagicMock(),
        )

        with pytest.raises(TimeoutError):
            await service.authenticate(payload, "req-id")

        secrets_service.boto_session.create_client.assert_not_called()
        secrets_service.fetch_secret.assert_not_called()


ROLE_ARN = "arn:aws:iam::123456789012:role/portunus-fed/projects/example/example-grant@projects.example"  # noqa: E501
WIF_SECRET = json.dumps(
    {
        "type": "anthropic_wif",
        "host": "api.example.com",
        "federation_role_arn": ROLE_ARN,
        "federation_rule_id": "fr_example",
        "organization_id": "org_example",
        "service_account_id": "sa_example",
        "workspace_id": "ws_example",
    }
)
CALLER = PrincipalInfo(
    arn="arn:aws:sts::123456789012:assumed-role/UserProfile_TestUser_example/s",
    account_id="123456789012",
    principal="assumed-role/UserProfile_TestUser_example",
    session_name="s",
    project="example",
)


def _payload(expires_in: timedelta = timedelta(hours=12)) -> AuthPayload:
    data = {
        "credentials": {
            "access_key_id": "AKIATEST",
            "secret_access_key": "SECRETTEST",
            "session_token": "TESTTOKEN",
        },
        "expiration": (datetime.now(timezone.utc) + expires_in).isoformat(),
        "secret_arn": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:key",
    }
    return AuthPayload.from_contents(
        base64.b64encode(json.dumps(data).encode()).decode()
    )


def _cache_backed_by(client: fakeredis.aioredis.FakeRedis) -> CacheService:
    state_service = MagicMock(spec=StateService)
    state_service.acquire_redis_connection = AsyncMock(return_value=client)
    return CacheService(state_service=state_service)


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def _service_for(raw_secret: str, cache: CacheService, mint: AsyncMock) -> AuthService:
    """An AuthService whose STS identity and secret fetch are canned."""
    sts_client = AsyncMock()
    sts_client.get_caller_identity = AsyncMock(return_value={"Arn": CALLER.arn})
    sts_client.__aenter__ = AsyncMock(return_value=sts_client)
    sts_client.__aexit__ = AsyncMock(return_value=None)
    boto_session = MagicMock()
    boto_session.create_client = MagicMock(return_value=sts_client)
    secrets_service = MagicMock(boto_session=boto_session)
    secrets_service.fetch_secret = AsyncMock(return_value=raw_secret)
    mint_service = MagicMock()
    mint_service.mint = mint
    return AuthService(
        secrets_service=secrets_service,
        cache_service=cache,
        mint_service=mint_service,
    )


def _minted(token: str = "sk-ant-oat01-example") -> MintedToken:
    return MintedToken(
        token=token, expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )


class TestAuthenticateWithMintSecrets:
    @pytest.mark.asyncio
    async def test_mint_secret_yields_a_bearer_result(self, fake_redis):
        cache = _cache_backed_by(fake_redis)
        mint = AsyncMock(return_value=_minted())
        service = _service_for(WIF_SECRET, cache, mint)
        payload = _payload()

        result = await service.authenticate(payload, "req", "api.example.com")

        assert result.api_key == "sk-ant-oat01-example"
        assert result.output_header == "authorization"
        assert result.output_prefix == "Bearer "
        assert result.expires_at == mint.return_value.expires_at
        assert result.principal_info == CALLER
        mint.assert_awaited_once()
        credentials, principal, secret = mint.await_args_list[0].args
        assert credentials is payload.credentials
        assert principal == CALLER
        assert isinstance(secret, AnthropicWifSecret)
        assert secret.federation_role_arn == ROLE_ARN

    @pytest.mark.asyncio
    async def test_minted_result_is_cached_until_shortly_before_expiry(
        self, fake_redis
    ):
        cache = _cache_backed_by(fake_redis)
        service = _service_for(WIF_SECRET, cache, AsyncMock(return_value=_minted()))
        payload = _payload()

        await service.authenticate(payload, "req", "api.example.com")

        ttl = await fake_redis.ttl(
            cache.generate_cache_key(payload.raw, "api.example.com")
        )
        assert 3600 - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS - 5 < ttl
        assert ttl <= 3600 - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS
        cached = await cache.get_cached_auth_result(payload.raw, "api.example.com")
        assert cached is not None
        assert cached.api_key == "sk-ant-oat01-example"
        assert cached.output_header == "authorization"

    @pytest.mark.asyncio
    async def test_stored_key_is_cached_for_the_cache_duration(self, fake_redis):
        cache = _cache_backed_by(fake_redis)
        mint = AsyncMock()
        service = _service_for("sk-static", cache, mint)
        payload = _payload()

        result = await service.authenticate(payload, "req", "api.example.com")

        assert result.api_key == "sk-static"
        assert result.output_header is None
        mint.assert_not_awaited()
        ttl = await fake_redis.ttl(
            cache.generate_cache_key(payload.raw, "api.example.com")
        )
        assert cache.cache_duration - 5 < ttl <= cache.cache_duration

    @pytest.mark.asyncio
    async def test_concurrent_requests_share_one_mint(self, fake_redis):
        cache = _cache_backed_by(fake_redis)

        async def slow_mint(*args, **kwargs):
            await asyncio.sleep(0.05)
            return _minted()

        mint = AsyncMock(side_effect=slow_mint)
        service = _service_for(WIF_SECRET, cache, mint)
        payload = _payload()

        results = await asyncio.gather(
            *(
                service.authenticate(payload, f"req-{i}", "api.example.com")
                for i in range(5)
            )
        )

        assert mint.await_count == 1
        assert {result.api_key for result in results} == {"sk-ant-oat01-example"}

    @pytest.mark.asyncio
    async def test_distinct_payloads_mint_independently(self, fake_redis):
        cache = _cache_backed_by(fake_redis)
        mint = AsyncMock(side_effect=lambda *a, **k: _minted())
        service = _service_for(WIF_SECRET, cache, mint)

        await asyncio.gather(
            service.authenticate(_payload(timedelta(hours=1)), "a", "api.example.com"),
            service.authenticate(_payload(timedelta(hours=2)), "b", "api.example.com"),
        )

        assert mint.await_count == 2

    @pytest.mark.asyncio
    async def test_token_cached_for_one_target_is_not_served_for_another(
        self, fake_redis
    ):
        """Same payload, different proxy: the host check must run, not a cache hit."""
        cache = _cache_backed_by(fake_redis)
        service = _service_for(WIF_SECRET, cache, AsyncMock(return_value=_minted()))
        payload = _payload()

        await service.authenticate(payload, "a", "api.example.com")

        with pytest.raises(AuthenticationError, match="not valid for target host"):
            await service.authenticate(payload, "b", "api.other.example")
        assert (
            await cache.get_cached_auth_result(payload.raw, "api.other.example") is None
        )

    @pytest.mark.asyncio
    async def test_stored_key_cached_for_one_target_is_a_miss_for_another(
        self, fake_redis
    ):
        cache = _cache_backed_by(fake_redis)
        service = _service_for("sk-static", cache, AsyncMock())
        payload = _payload()

        await service.authenticate(payload, "req", "api.example.com")

        assert (
            await cache.get_cached_auth_result(payload.raw, "api.example.com")
            is not None
        )
        assert (
            await cache.get_cached_auth_result(payload.raw, "api.other.example") is None
        )

    @pytest.mark.asyncio
    async def test_mint_lock_is_per_payload_and_target(self, fake_redis):
        service = _service_for(WIF_SECRET, _cache_backed_by(fake_redis), AsyncMock())
        payload = _payload()

        example = service._mint_lock(payload, "api.example.com")
        other = service._mint_lock(payload, "api.other.example")

        assert example is not other
        assert service._mint_lock(payload, "api.example.com") is example
        assert (
            service._mint_lock(_payload(timedelta(hours=2)), "api.example.com")
            is not example
        )

    @pytest.mark.asyncio
    async def test_host_mismatch_is_rejected_before_minting(self, fake_redis):
        mint = AsyncMock(return_value=_minted())
        service = _service_for(WIF_SECRET, _cache_backed_by(fake_redis), mint)

        with pytest.raises(AuthenticationError):
            await service.authenticate(_payload(), "req", "api.other.example")

        mint.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_mint_failure_surfaces_as_authentication_error(self, fake_redis):
        mint = AsyncMock(side_effect=AuthenticationError("Token exchange failed"))
        cache = _cache_backed_by(fake_redis)
        service = _service_for(WIF_SECRET, cache, mint)
        payload = _payload()

        with pytest.raises(AuthenticationError, match="Token exchange failed"):
            await service.authenticate(payload, "req", "api.example.com")

        assert (
            await cache.get_cached_auth_result(payload.raw, "api.example.com") is None
        )

    @pytest.mark.asyncio
    async def test_expired_credentials_during_mint_surface_as_credentials_error(
        self, fake_redis
    ):
        mint = AsyncMock(side_effect=CredentialsError("AWS credentials have expired"))
        service = _service_for(WIF_SECRET, _cache_backed_by(fake_redis), mint)

        with pytest.raises(CredentialsError):
            await service.authenticate(_payload(), "req", "api.example.com")

    @pytest.mark.asyncio
    async def test_upstream_failure_during_mint_passes_through_unchanged(
        self, fake_redis
    ):
        error = UpstreamServiceError("STS is unavailable")
        mint = AsyncMock(side_effect=error)
        service = _service_for(WIF_SECRET, _cache_backed_by(fake_redis), mint)

        with pytest.raises(UpstreamServiceError) as exc_info:
            await service.authenticate(_payload(), "req", "api.example.com")

        assert exc_info.value is error
