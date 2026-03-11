"""Tests for the authentication service, including credential error handling."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from botocore.exceptions import ClientError

from portunus.exceptions import CredentialsError
from portunus.models import AwsCredentials
from portunus.services.auth_service import AuthService


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
