"""Tests for the pluggable backend architecture."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from portunus.backends.aws.identity import parse_identity_from_arn
from portunus.backends.debug.publisher import DebugPublisher
from portunus.backends.protocols import AuthBackend, StreamPublisher
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
    ServiceError,
)
from portunus.models import AuthResult, PrincipalInfo, SigningKey


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------
class TestProtocolCompliance:
    """Verify implementations satisfy the Protocol contracts."""

    def test_debug_publisher_is_stream_publisher(self):
        publisher = DebugPublisher()
        assert isinstance(publisher, StreamPublisher)

    def test_aws_auth_backend_is_auth_backend(self):
        from portunus.backends.aws.auth import AwsAuthBackend

        backend = AwsAuthBackend()
        assert isinstance(backend, AuthBackend)

    def test_kinesis_publisher_is_stream_publisher(self):
        from portunus.backends.aws.publisher import KinesisPublisher

        publisher = KinesisPublisher()
        assert isinstance(publisher, StreamPublisher)


# ---------------------------------------------------------------------------
# DebugPublisher
# ---------------------------------------------------------------------------
class TestDebugPublisher:
    @pytest.mark.asyncio
    async def test_publish_returns_true(self):
        publisher = DebugPublisher()
        result = await publisher.publish("test-stream", {"key": "value"}, "pk-123")
        assert result is True

    @pytest.mark.asyncio
    async def test_publish_handles_empty_data(self):
        publisher = DebugPublisher()
        result = await publisher.publish("stream", {}, "pk")
        assert result is True

    @pytest.mark.asyncio
    async def test_publish_handles_empty_stream_name(self):
        """DebugPublisher always succeeds — even with empty stream name."""
        publisher = DebugPublisher()
        result = await publisher.publish("", {}, "pk")
        assert result is True

    @pytest.mark.asyncio
    async def test_publish_logs_at_debug(self, caplog):
        """Verify debug publisher actually logs something."""
        import logging

        publisher = DebugPublisher()
        with caplog.at_level(logging.DEBUG, logger="api.access"):
            await publisher.publish("my-stream", {"a": 1}, "pk")
        assert "my-stream" in caplog.text
        assert "debug" in caplog.text


# ---------------------------------------------------------------------------
# KinesisPublisher (mocked boto)
# ---------------------------------------------------------------------------
class TestKinesisPublisher:
    @pytest.mark.asyncio
    async def test_publish_success(self):
        from portunus.backends.aws.publisher import KinesisPublisher

        publisher = KinesisPublisher()
        mock_client = AsyncMock()
        mock_client.put_record.return_value = {
            "ShardId": "shard-001",
            "SequenceNumber": "12345678901234567890",
        }
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        publisher.boto_session = MagicMock()
        publisher.boto_session.create_client.return_value = mock_client

        result = await publisher.publish("my-stream", {"key": "val"}, "pk-1")
        assert result is True
        mock_client.put_record.assert_awaited_once()
        call_kwargs = mock_client.put_record.call_args.kwargs
        assert call_kwargs["StreamName"] == "my-stream"
        assert call_kwargs["PartitionKey"] == "pk-1"

    @pytest.mark.asyncio
    async def test_publish_skips_empty_stream_name(self):
        from portunus.backends.aws.publisher import KinesisPublisher

        publisher = KinesisPublisher()
        result = await publisher.publish("", {"key": "val"}, "pk-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_publish_raises_service_error_on_failure(self):
        from portunus.backends.aws.publisher import KinesisPublisher

        publisher = KinesisPublisher()
        mock_client = AsyncMock()
        mock_client.put_record.side_effect = RuntimeError("connection lost")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        publisher.boto_session = MagicMock()
        publisher.boto_session.create_client.return_value = mock_client

        with pytest.raises(ServiceError, match="connection lost"):
            await publisher.publish("stream", {"k": "v"}, "pk")

    @pytest.mark.asyncio
    async def test_publish_reraises_timeout(self):
        from portunus.backends.aws.publisher import KinesisPublisher

        publisher = KinesisPublisher()
        mock_client = AsyncMock()
        mock_client.put_record.side_effect = TimeoutError("timed out")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        publisher.boto_session = MagicMock()
        publisher.boto_session.create_client.return_value = mock_client

        with pytest.raises(TimeoutError):
            await publisher.publish("stream", {"k": "v"}, "pk")


# ---------------------------------------------------------------------------
# PublishService with mock publisher
# ---------------------------------------------------------------------------
class TestPublishServiceDelegation:
    """Verify PublishService constructs records and delegates to publisher."""

    @pytest.fixture(autouse=True)
    def _patch_kinesis_config(self):
        """Ensure kinesis stream names are set for all delegation tests."""
        with patch("portunus.services.publish_service.config") as mock_cfg:
            mock_cfg.kinesis.metadata_stream_name = "test-metadata"
            mock_cfg.kinesis.request_headers_stream_name = "test-req-headers"
            mock_cfg.kinesis.request_body_stream_name = "test-req-body"
            mock_cfg.kinesis.request_trailers_stream_name = "test-req-trailers"
            mock_cfg.kinesis.response_headers_stream_name = "test-resp-headers"
            mock_cfg.kinesis.response_body_stream_name = "test-resp-body"
            mock_cfg.kinesis.response_trailers_stream_name = "test-resp-trailers"
            yield mock_cfg

    @pytest.fixture
    def mock_publisher(self):
        p = AsyncMock(spec=StreamPublisher)
        p.publish.return_value = True
        return p

    @pytest.fixture
    def publish_service(self, mock_publisher):
        from portunus.services.publish_service import PublishService

        return PublishService(publisher=mock_publisher)

    @pytest.mark.asyncio
    async def test_publish_metadata_delegates(self, publish_service, mock_publisher):
        result = await publish_service.publish_metadata(
            request_id="req-1",
            timestamp="2024-01-01T00:00:00Z",
            principal_info={
                "account_id": "123",
                "principal": "role/test",
                "arn": "arn:aws:sts::123:assumed-role/test/session",
                "project": "myproj",
                "session_name": "session",
            },
        )
        assert result is True
        mock_publisher.publish.assert_awaited_once()
        call_args = mock_publisher.publish.call_args
        record_data = call_args[0][1]
        assert record_data["request_id"] == "req-1"
        assert record_data["account_id"] == "123"
        assert record_data["project"] == "myproj"

    @pytest.mark.asyncio
    async def test_publish_request_headers_delegates(
        self, publish_service, mock_publisher
    ):
        result = await publish_service.publish_request_headers(
            request_id="req-2",
            headers={"Content-Type": "application/json"},
            timestamp="2024-01-01T00:00:00Z",
        )
        assert result is True
        record_data = mock_publisher.publish.call_args[0][1]
        assert record_data["request_id"] == "req-2"
        assert record_data["raw_headers"] == {"Content-Type": "application/json"}

    @pytest.mark.asyncio
    async def test_publish_request_body_base64_encodes(
        self, publish_service, mock_publisher
    ):
        result = await publish_service.publish_request_body(
            request_id="req-3",
            body_bytes=b"hello world",
            timestamp="2024-01-01T00:00:00Z",
            chunk_id=0,
            num_chunks=1,
        )
        assert result is True
        record_data = mock_publisher.publish.call_args[0][1]
        import base64

        assert base64.b64decode(record_data["body"]) == b"hello world"
        assert record_data["body_size"] == 11
        assert record_data["chunk_id"] == 0

    @pytest.mark.asyncio
    async def test_publish_response_body_base64_encodes(
        self, publish_service, mock_publisher
    ):
        result = await publish_service.publish_response_body(
            request_id="req-4",
            body_bytes=b"\x00\x01\x02",
            timestamp="2024-01-01T00:00:00Z",
            chunk_id=1,
            num_chunks=3,
        )
        assert result is True
        record_data = mock_publisher.publish.call_args[0][1]
        import base64

        assert base64.b64decode(record_data["body"]) == b"\x00\x01\x02"
        assert record_data["num_chunks"] == 3

    @pytest.mark.asyncio
    async def test_publish_skips_when_stream_unconfigured(
        self, _patch_kinesis_config, mock_publisher
    ):
        """When stream name is None in config, publish returns False."""
        from portunus.services.publish_service import PublishService

        _patch_kinesis_config.kinesis.metadata_stream_name = None
        svc = PublishService(publisher=mock_publisher)
        result = await svc.publish_metadata("req", "ts", {"account_id": "x"})
        assert result is False
        mock_publisher.publish.assert_not_awaited()


# ---------------------------------------------------------------------------
# AuthService with mock backend
# ---------------------------------------------------------------------------
class TestAuthServiceWithMockBackend:
    """Test AuthService orchestration around a mock AuthBackend."""

    @pytest.fixture
    def mock_backend(self):
        backend = AsyncMock(spec=AuthBackend)
        backend.authenticate.return_value = AuthResult(
            api_key="sk-test-key",
            signing_key=None,
            principal_info=PrincipalInfo(
                arn="arn:aws:sts::123:assumed-role/TestRole/session",
                account_id="123",
                principal="assumed-role/TestRole",
                session_name="session",
                project="testproj",
            ),
        )
        backend.sign_request.return_value = None
        return backend

    @pytest.fixture
    def mock_cache(self):
        cache = AsyncMock()
        cache.get_cached_auth_result.return_value = None
        cache.cache_auth_result.return_value = None
        return cache

    @pytest.fixture
    def auth_service(self, mock_backend, mock_cache):
        from portunus.services.auth_service import AuthService

        return AuthService(auth_backend=mock_backend, cache_service=mock_cache)

    @pytest.mark.asyncio
    async def test_delegates_to_backend(self, auth_service, mock_backend, mock_cache):
        result = await auth_service.authenticate(
            "raw-payload", "req-1", "target.example.com"
        )
        assert result.api_key == "sk-test-key"
        mock_backend.authenticate.assert_awaited_once_with(
            "raw-payload", "req-1", "target.example.com"
        )
        # Should cache the result
        mock_cache.cache_auth_result.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_cached_result(self, auth_service, mock_backend, mock_cache):
        cached = AuthResult(
            api_key="sk-cached",
            signing_key=None,
            principal_info=PrincipalInfo(),
        )
        mock_cache.get_cached_auth_result.return_value = cached

        result = await auth_service.authenticate("payload", "req-2")
        assert result.api_key == "sk-cached"
        mock_backend.authenticate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cache_error_falls_through_to_backend(
        self, auth_service, mock_backend, mock_cache
    ):
        mock_cache.get_cached_auth_result.side_effect = RuntimeError("redis down")

        result = await auth_service.authenticate("payload", "req-3")
        assert result.api_key == "sk-test-key"
        mock_backend.authenticate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_propagates_payload_error(
        self, auth_service, mock_backend, mock_cache
    ):
        mock_backend.authenticate.side_effect = PayloadError("bad payload")

        with pytest.raises(PayloadError, match="bad payload"):
            await auth_service.authenticate("bad", "req-4")

    @pytest.mark.asyncio
    async def test_propagates_credentials_error(
        self, auth_service, mock_backend, mock_cache
    ):
        mock_backend.authenticate.side_effect = CredentialsError("expired")

        with pytest.raises(CredentialsError, match="expired"):
            await auth_service.authenticate("payload", "req-5")

    @pytest.mark.asyncio
    async def test_wraps_unexpected_error_as_auth_error(
        self, auth_service, mock_backend, mock_cache
    ):
        mock_backend.authenticate.side_effect = RuntimeError("oops")

        with pytest.raises(AuthenticationError, match="oops"):
            await auth_service.authenticate("payload", "req-6")

    @pytest.mark.asyncio
    async def test_sign_request_delegates(self, auth_service, mock_backend):
        auth_result = AuthResult(
            api_key="key",
            signing_key=SigningKey(
                provider_id="sig_123", kms_key_arn="arn:aws:kms:..."
            ),
            principal_info=PrincipalInfo(),
        )
        mock_backend.sign_request.return_value = {
            "Signature": "sig1=:abc:",
            "Signature-Input": 'sig1=("@method")',
        }

        result = await auth_service.sign_request(
            "raw-payload", MagicMock(), auth_result
        )
        assert result is not None
        assert "Signature" in result
        mock_backend.sign_request.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sign_request_returns_none_without_signing_key(
        self, auth_service, mock_backend
    ):
        auth_result = AuthResult(
            api_key="key",
            signing_key=None,
            principal_info=PrincipalInfo(),
        )
        mock_backend.sign_request.return_value = None

        result = await auth_service.sign_request(
            "raw-payload", MagicMock(), auth_result
        )
        assert result is None


# ---------------------------------------------------------------------------
# AwsAuthBackend (mocked AWS clients)
# ---------------------------------------------------------------------------
class TestAwsAuthBackend:
    """Test AwsAuthBackend with mocked AWS services."""

    @pytest.fixture
    def backend(self):
        from portunus.backends.aws.auth import AwsAuthBackend

        return AwsAuthBackend(role_pattern=r"^UserProfile_[^_]+_(?P<project>.+)$")

    @pytest.mark.asyncio
    async def test_authenticate_success(self, backend):
        """Full authenticate flow with mocked STS + Secrets Manager."""
        mock_sts_client = AsyncMock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": (
                "arn:aws:sts::123456789012:"
                "assumed-role/UserProfile_Name_myproject/session"
            ),
            "Account": "123456789012",
        }
        mock_sts_client.__aenter__ = AsyncMock(return_value=mock_sts_client)
        mock_sts_client.__aexit__ = AsyncMock(return_value=False)

        mock_sm_client = AsyncMock()
        mock_sm_client.get_secret_value.return_value = {"SecretString": "sk-my-api-key"}
        mock_sm_client.__aenter__ = AsyncMock(return_value=mock_sm_client)
        mock_sm_client.__aexit__ = AsyncMock(return_value=False)

        def create_client(service, **kwargs):
            if service == "sts":
                return mock_sts_client
            if service == "secretsmanager":
                return mock_sm_client
            raise ValueError(f"unexpected service: {service}")

        backend.boto_session = MagicMock()
        backend.boto_session.create_client = create_client

        # Build a valid encoded payload
        import base64
        import json

        payload_data = {
            "credentials": {
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
                "session_token": "token",
            },
            "secret_arn": "arn:aws:secretsmanager:eu-west-2:123:secret:test",
        }
        raw_payload = base64.b64encode(json.dumps(payload_data).encode()).decode()

        result = await backend.authenticate(raw_payload, "req-1")

        assert result.api_key == "sk-my-api-key"
        assert result.principal_info.project == "myproject"
        assert result.principal_info.account_id == "123456789012"
        assert result.signing_key is None

    @pytest.mark.asyncio
    async def test_authenticate_invalid_payload_raises(self, backend):
        with pytest.raises(PayloadError, match="decode"):
            await backend.authenticate("not-valid-base64!!!", "req-2")

    @pytest.mark.asyncio
    async def test_authenticate_empty_credentials_raises_payload_error(self, backend):
        """Empty credentials are caught during payload validation."""
        import base64
        import json

        payload_data = {
            "credentials": {
                "access_key_id": "",
                "secret_access_key": "",
            },
            "secret_arn": "arn:aws:secretsmanager:eu-west-2:123:secret:test",
        }
        raw_payload = base64.b64encode(json.dumps(payload_data).encode()).decode()

        with pytest.raises(PayloadError):
            await backend.authenticate(raw_payload, "req-3")

    @pytest.mark.asyncio
    async def test_authenticate_secrets_manager_error_raises(self, backend):
        """Secrets Manager failure should raise FetchSecretError."""
        mock_sts_client = AsyncMock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:sts::123:assumed-role/TestRole/session",
        }
        mock_sts_client.__aenter__ = AsyncMock(return_value=mock_sts_client)
        mock_sts_client.__aexit__ = AsyncMock(return_value=False)

        mock_sm_client = AsyncMock()
        mock_sm_client.get_secret_value.side_effect = RuntimeError("access denied")
        mock_sm_client.__aenter__ = AsyncMock(return_value=mock_sm_client)
        mock_sm_client.__aexit__ = AsyncMock(return_value=False)

        def create_client(service, **kwargs):
            if service == "sts":
                return mock_sts_client
            return mock_sm_client

        backend.boto_session = MagicMock()
        backend.boto_session.create_client = create_client

        import base64
        import json

        payload_data = {
            "credentials": {
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
                "session_token": "token",
            },
            "secret_arn": "arn:aws:secretsmanager:eu-west-2:123:secret:test",
        }
        raw_payload = base64.b64encode(json.dumps(payload_data).encode()).decode()

        with pytest.raises(FetchSecretError):
            await backend.authenticate(raw_payload, "req-4")

    @pytest.mark.asyncio
    async def test_sign_request_returns_none_without_signing_key(self, backend):
        auth_result = AuthResult(
            api_key="key",
            signing_key=None,
            principal_info=PrincipalInfo(),
        )
        result = await backend.sign_request("payload", MagicMock(), auth_result)
        assert result is None


# ---------------------------------------------------------------------------
# Identity parsing
# ---------------------------------------------------------------------------
class TestIdentityParsing:
    """Tests for configurable ARN identity parsing."""

    def test_no_pattern_returns_none_project(self):
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:"
            "assumed-role/UserProfile_Name_myproject/session",
            role_pattern=None,
        )
        assert result.principal == "assumed-role/UserProfile_Name_myproject"
        assert result.session_name == "session"
        assert result.project is None

    def test_aisi_pattern_extracts_project(self):
        pattern = r"^UserProfile_[^_]+_(?P<project>.+)$"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:"
            "assumed-role/UserProfile_Name_myproject/session",
            role_pattern=pattern,
        )
        assert result.project == "myproject"

    def test_aisi_pattern_with_underscores_in_project(self):
        pattern = r"^UserProfile_[^_]+_(?P<project>.+)$"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:"
            "assumed-role/UserProfile_Name_proj_abc/session",
            role_pattern=pattern,
        )
        assert result.project == "proj_abc"

    def test_custom_pattern(self):
        pattern = r"^team-(?P<project>[^-]+)-"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:" "assumed-role/team-engineering-prod/session",
            role_pattern=pattern,
        )
        assert result.project == "engineering"

    def test_pattern_no_match_returns_none_project(self):
        pattern = r"^UserProfile_[^_]+_(?P<project>.+)$"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:" "assumed-role/SomeOtherRole/session",
            role_pattern=pattern,
        )
        assert result.principal == "assumed-role/SomeOtherRole"
        assert result.project is None

    def test_non_assumed_role_arn(self):
        result = parse_identity_from_arn(
            "arn:aws:iam::123456789012:user/test-user",
            role_pattern=r"^UserProfile_[^_]+_(?P<project>.+)$",
        )
        assert result.account_id == "123456789012"
        assert result.principal is None
        assert result.project is None

    def test_empty_arn(self):
        result = parse_identity_from_arn("")
        assert result.account_id == "unknown"
        assert result.principal is None
        assert result.project is None

    def test_basic_fields_always_populated(self):
        result = parse_identity_from_arn(
            "arn:aws:sts::999888777666:" "assumed-role/MyRole/my-session",
            role_pattern=None,
        )
        assert result.arn.startswith("arn:aws:sts::")
        assert result.account_id == "999888777666"
        assert result.session_name == "my-session"


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------
class TestBackendFactory:
    def test_get_auth_backend_aws(self):
        from portunus.backends import get_auth_backend
        from portunus.config import get_config

        cfg = get_config()
        backend = get_auth_backend(cfg)
        assert isinstance(backend, AuthBackend)

    def test_get_stream_publisher_kinesis(self):
        from portunus.backends import get_stream_publisher
        from portunus.config import get_config

        cfg = get_config()
        publisher = get_stream_publisher(cfg)
        assert isinstance(publisher, StreamPublisher)

    def test_get_stream_publisher_debug(self):
        from portunus.backends import get_stream_publisher
        from portunus.config import PortunusConfig

        cfg = PortunusConfig(log_backend="debug")
        publisher = get_stream_publisher(cfg)
        assert isinstance(publisher, DebugPublisher)

    def test_unknown_auth_backend_raises(self):
        from portunus.backends import get_auth_backend
        from portunus.config import PortunusConfig

        cfg = PortunusConfig(auth_backend="nonexistent")
        with pytest.raises(ValueError, match="nonexistent"):
            get_auth_backend(cfg)

    def test_unknown_log_backend_raises(self):
        from portunus.backends import get_stream_publisher
        from portunus.config import PortunusConfig

        cfg = PortunusConfig(log_backend="nonexistent")
        with pytest.raises(ValueError, match="nonexistent"):
            get_stream_publisher(cfg)
