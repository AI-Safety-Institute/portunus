"""Tests for the secrets service."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from botocore.exceptions import ClientError

from portunus.exceptions import FetchSecretError
from portunus.models import AuthPayload, AwsCredentials
from portunus.services.secrets_service import SecretsService


@pytest.fixture
def secrets_service():
    """Create a SecretsService instance with mocked boto session."""
    service = SecretsService()
    service.boto_session = MagicMock()
    return service


@pytest.fixture
def valid_auth_payload():
    """Create a valid AuthPayload for testing."""
    return AuthPayload(
        raw="test-payload",
        credentials=AwsCredentials(
            access_key_id="AKIATEST123",
            secret_access_key="secretkey123",
            session_token="sessiontoken123",
        ),
        secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
    )


class TestFetchSecret:
    """Tests for the fetch_secret method."""

    @pytest.mark.asyncio
    async def test_client_error_raises_fetch_secret_error(
        self, secrets_service, valid_auth_payload
    ):
        """Test that ClientErrors raise FetchSecretError."""
        mock_client = AsyncMock()
        mock_client.get_secret_value = AsyncMock(
            side_effect=ClientError(
                error_response={
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Secret not found",
                    }
                },
                operation_name="GetSecretValue",
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        secrets_service.boto_session.create_client = MagicMock(return_value=mock_client)

        with pytest.raises(FetchSecretError):
            await secrets_service.fetch_secret(valid_auth_payload)

    @pytest.mark.asyncio
    async def test_successful_fetch_returns_secret_string(
        self, secrets_service, valid_auth_payload
    ):
        """Test that successful fetch returns the secret string."""
        mock_client = AsyncMock()
        mock_client.get_secret_value = AsyncMock(
            return_value={"SecretString": "my-api-key"}
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        secrets_service.boto_session.create_client = MagicMock(return_value=mock_client)

        result = await secrets_service.fetch_secret(valid_auth_payload)

        assert result == "my-api-key"


class TestFetchServiceSecret:
    """Secrets read with Portunus's own credentials, for on-behalf-of callers."""

    def _client(self, **get_secret_value):
        client = AsyncMock()
        client.get_secret_value = AsyncMock(**get_secret_value)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        return client

    @pytest.mark.asyncio
    async def test_uses_ambient_credentials_not_a_callers(self, secrets_service):
        client = self._client(return_value={"SecretString": "sk-proxy"})
        secrets_service.boto_session.create_client = MagicMock(return_value=client)

        assert (
            await secrets_service.fetch_service_secret("arn:aws:secretsmanager:x")
            == "sk-proxy"
        )
        _, kwargs = secrets_service.boto_session.create_client.call_args
        assert (
            not {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
            & kwargs.keys()
        )
        client.get_secret_value.assert_awaited_once_with(
            SecretId="arn:aws:secretsmanager:x"
        )

    @pytest.mark.asyncio
    async def test_failure_raises_fetch_secret_error(self, secrets_service):
        client = self._client(
            side_effect=ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                "GetSecretValue",
            )
        )
        secrets_service.boto_session.create_client = MagicMock(return_value=client)
        with pytest.raises(FetchSecretError):
            await secrets_service.fetch_service_secret("arn:aws:secretsmanager:x")

    @pytest.mark.asyncio
    async def test_works_behind_the_credential_keyed_client_pool(self):
        """The pool only serves explicit credential sets; ambient reads bypass it."""
        from portunus.services.state_service import PooledBotoSession

        client = self._client(return_value={"SecretString": "sk-proxy"})
        base = MagicMock()
        base.create_client = MagicMock(return_value=client)
        state = MagicMock()
        state.boto_session = base
        state.get_pooled_aws_client = AsyncMock(side_effect=AssertionError("pool used"))
        service = SecretsService(boto_session=PooledBotoSession(state))

        secret = await service.fetch_service_secret("arn:aws:secretsmanager:x")
        assert secret == "sk-proxy"
        base.create_client.assert_called_once()
