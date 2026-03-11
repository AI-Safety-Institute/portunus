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
