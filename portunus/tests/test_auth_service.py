"""Tests for the authentication service, including credential error handling."""

from unittest.mock import AsyncMock, MagicMock

import pytest
import redis.exceptions
from botocore.exceptions import ClientError

from portunus.exceptions import CredentialsError
from portunus.models import AuthPayload, AuthResult, AwsCredentials, PrincipalInfo
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.state_service import StateService


@pytest.fixture
def auth_service():
    """Create an AuthService instance with mocked dependencies."""
    mock_secrets_service = MagicMock()
    mock_secrets_service.boto_session = MagicMock()
    mock_cache_service = MagicMock()
    mock_cache_service.get_cached_auth_result = AsyncMock(return_value=None)
    mock_cache_service.cache_auth_result = AsyncMock(return_value=True)

    return AuthService(
        secrets_service=mock_secrets_service,
        cache_service=mock_cache_service,
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
            signing_key=None,
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
        state_service = StateService()
        state_service.redis_client = redis_client
        secrets_service = MagicMock()
        secrets_service.boto_session = MagicMock()
        secrets_service.fetch_secret = AsyncMock()
        service = AuthService(
            secrets_service=secrets_service,
            cache_service=CacheService(state_service=state_service),
        )

        with pytest.raises(TimeoutError):
            await service.authenticate(payload, "req-id")

        secrets_service.boto_session.create_client.assert_not_called()
        secrets_service.fetch_secret.assert_not_called()


class TestLocalAuthCache:
    """The in-process L1 tier in front of Redis."""

    @staticmethod
    def _service(clock):
        from portunus.services.local_auth_cache import LocalAuthCache

        secrets_service = MagicMock()
        secrets_service.boto_session = MagicMock()
        secrets_service.fetch_secret = AsyncMock(return_value="sk-live")
        cache_service = MagicMock()
        cache_service.get_cached_auth_result = AsyncMock(return_value=None)
        cache_service.cache_auth_result = AsyncMock(return_value=True)
        service = AuthService(
            secrets_service=secrets_service,
            cache_service=cache_service,
            local_cache=LocalAuthCache(
                ttl_seconds=30, stale_seconds=300, max_entries=100, clock=clock
            ),
        )
        install_sts_client(service)
        return service

    @pytest.fixture
    def clock(self):
        class Clock:
            now = 1000.0

            def __call__(self):
                return self.now

        return Clock()

    @pytest.mark.asyncio
    async def test_second_request_served_from_memory(self, clock, payload):
        service = self._service(clock)
        first = await service.authenticate(payload, "r1", "api.openai.com")
        second = await service.authenticate(payload, "r2", "api.openai.com")
        assert first == second
        assert service.cache_service.get_cached_auth_result.await_count == 1
        assert service.secrets_service.fetch_secret.await_count == 1

    @pytest.mark.asyncio
    async def test_redis_hit_populates_memory(self, clock, payload):
        service = self._service(clock)
        cached = AuthResult(
            api_key="sk-cached", signing_key=None, principal_info=PrincipalInfo()
        )
        service.cache_service.get_cached_auth_result.return_value = cached
        await service.authenticate(payload, "r1", "api.openai.com")
        result = await service.authenticate(payload, "r2", "api.openai.com")
        assert result.api_key == "sk-cached"
        assert service.cache_service.get_cached_auth_result.await_count == 1
        service.secrets_service.fetch_secret.assert_not_called()

    @pytest.mark.asyncio
    async def test_target_host_is_part_of_memory_key(self, clock, payload):
        service = self._service(clock)
        await service.authenticate(payload, "r1", "api.openai.com")
        await service.authenticate(payload, "r2", "api.anthropic.com")
        assert service.cache_service.get_cached_auth_result.await_count == 2

    @pytest.mark.asyncio
    async def test_refreshes_from_redis_after_ttl(self, clock, payload):
        service = self._service(clock)
        await service.authenticate(payload, "r1", "h")
        clock.now += 31
        await service.authenticate(payload, "r2", "h")
        assert service.cache_service.get_cached_auth_result.await_count == 2

    @pytest.mark.asyncio
    async def test_redis_timeout_serves_stale_entry(self, clock, payload):
        service = self._service(clock)
        first = await service.authenticate(payload, "r1", "h")
        clock.now += 60
        service.cache_service.get_cached_auth_result.side_effect = (
            redis.exceptions.TimeoutError()
        )
        assert await service.authenticate(payload, "r2", "h") == first
        assert service.secrets_service.fetch_secret.await_count == 1

    @pytest.mark.asyncio
    async def test_redis_error_serves_stale_without_sts(self, clock, payload):
        service = self._service(clock)
        first = await service.authenticate(payload, "r1", "h")
        clock.now += 60
        service.cache_service.get_cached_auth_result.side_effect = (
            redis.exceptions.ConnectionError()
        )
        assert await service.authenticate(payload, "r2", "h") == first
        assert service.secrets_service.fetch_secret.await_count == 1
        assert service.boto_session.create_client.call_count == 1

    @pytest.mark.asyncio
    async def test_redis_timeout_without_stale_entry_rejects(self, clock, payload):
        service = self._service(clock)
        service.cache_service.get_cached_auth_result.side_effect = (
            redis.exceptions.TimeoutError()
        )
        with pytest.raises(TimeoutError):
            await service.authenticate(payload, "r1", "h")
        service.secrets_service.fetch_secret.assert_not_called()

    @pytest.mark.asyncio
    async def test_concurrent_cold_requests_share_one_redis_read(self, clock, payload):
        import asyncio

        service = self._service(clock)
        release = asyncio.Event()

        async def slow_get(*_args):
            await release.wait()
            return None

        service.cache_service.get_cached_auth_result.side_effect = slow_get
        tasks = [
            asyncio.create_task(service.authenticate(payload, f"r{i}", "h"))
            for i in range(20)
        ]
        await asyncio.sleep(0)
        release.set()
        results = await asyncio.gather(*tasks)
        assert len({r.api_key for r in results}) == 1
        assert service.cache_service.get_cached_auth_result.await_count == 1
        assert service.secrets_service.fetch_secret.await_count == 1

    @pytest.mark.asyncio
    async def test_failures_not_cached(self, clock, payload):
        service = self._service(clock)
        service.secrets_service.fetch_secret.side_effect = CredentialsError("nope")
        for _ in range(2):
            with pytest.raises(CredentialsError):
                await service.authenticate(payload, "r", "h")
        assert service.secrets_service.fetch_secret.await_count == 2


class TestBoundedFallback:
    """Full authentication (STS + Secrets Manager) runs under a cap."""

    @pytest.mark.asyncio
    async def test_sheds_when_fallback_slots_exhausted(
        self, auth_service, valid_credentials, monkeypatch
    ):
        import asyncio

        from portunus.exceptions import AuthOverloadedError

        auth_service._fallback_slots = asyncio.Semaphore(1)
        auth_service._fallback_acquire_timeout_s = 0.05
        install_sts_client(auth_service)
        release = asyncio.Event()

        async def slow_fetch(_payload):
            await release.wait()
            return "sk-live"

        auth_service.secrets_service.fetch_secret = AsyncMock(side_effect=slow_fetch)

        def make_payload(raw):
            return AuthPayload(
                raw=raw,
                credentials=valid_credentials,
                secret_arn="arn:aws:secretsmanager:eu-west-2:1:secret:x",
            )

        first = asyncio.create_task(
            auth_service.authenticate(make_payload("a"), "r1", "h")
        )
        await asyncio.sleep(0.01)
        with pytest.raises(AuthOverloadedError):
            await auth_service.authenticate(make_payload("b"), "r2", "h")
        release.set()
        assert (await first).api_key == "sk-live"
        # Slot released: the next distinct key authenticates normally.
        result = await auth_service.authenticate(make_payload("c"), "r3", "h")
        assert result.api_key == "sk-live"

    @pytest.mark.asyncio
    async def test_slot_released_on_failure(self, auth_service, payload):
        import asyncio

        auth_service._fallback_slots = asyncio.Semaphore(1)
        auth_service.secrets_service.fetch_secret = AsyncMock(
            side_effect=CredentialsError("nope")
        )
        install_sts_client(auth_service)
        for _ in range(3):
            with pytest.raises(CredentialsError):
                await auth_service.authenticate(payload, "r", "h")
        assert not auth_service._fallback_slots.locked()
