"""Tests for the authentication service, including credential error handling."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from botocore.exceptions import ClientError

from portunus.backends.aws.auth import AwsAuthBackend
from portunus.exceptions import CredentialsError
from portunus.models import AwsCredentials
from portunus.services.auth_service import AuthService


@pytest.fixture
def aws_backend():
    """Create an AwsAuthBackend with mocked boto session."""
    backend = AwsAuthBackend()
    backend.boto_session = MagicMock()
    return backend


@pytest.fixture
def auth_service(aws_backend):
    """Create an AuthService with mocked dependencies."""
    mock_cache_service = MagicMock()
    mock_cache_service.get_cached_auth_result = AsyncMock(return_value=None)
    mock_cache_service.cache_auth_result = AsyncMock(return_value=True)

    return AuthService(
        auth_backend=aws_backend,
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


class TestGetAwsIdentity:
    """Tests for the AwsAuthBackend._get_aws_identity method."""

    @pytest.mark.asyncio
    async def test_expired_token_raises_credentials_error(
        self, aws_backend, valid_credentials
    ):
        """Test that ExpiredToken from STS raises CredentialsError."""
        mock_sts_client = AsyncMock()
        mock_sts_client.get_caller_identity = AsyncMock(
            side_effect=ClientError(
                error_response={
                    "Error": {
                        "Code": "ExpiredToken",
                        "Message": "Token has expired",
                    }
                },
                operation_name="GetCallerIdentity",
            )
        )
        mock_sts_client.__aenter__ = AsyncMock(return_value=mock_sts_client)
        mock_sts_client.__aexit__ = AsyncMock(return_value=None)

        aws_backend.boto_session.create_client = MagicMock(return_value=mock_sts_client)

        with pytest.raises(CredentialsError) as exc_info:
            await aws_backend._get_aws_identity(valid_credentials)

        assert "expired" in str(exc_info.value.message).lower()

    @pytest.mark.asyncio
    async def test_other_client_error_raises_credentials_error(
        self, aws_backend, valid_credentials
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

        aws_backend.boto_session.create_client = MagicMock(return_value=mock_sts_client)

        with pytest.raises(CredentialsError) as exc_info:
            await aws_backend._get_aws_identity(valid_credentials)

        assert "Failed to get caller identity" in str(exc_info.value.message)

    @pytest.mark.asyncio
    async def test_invalid_credentials_raises_credentials_error(self, aws_backend):
        """Test that credentials failing is_valid() raise CredentialsError."""
        invalid_credentials = MagicMock(spec=AwsCredentials)
        invalid_credentials.is_valid.return_value = False

        with pytest.raises(CredentialsError):
            await aws_backend._get_aws_identity(invalid_credentials)

    @pytest.mark.asyncio
    async def test_none_credentials_raises_credentials_error(self, aws_backend):
        """Test that None credentials raise CredentialsError."""
        with pytest.raises(CredentialsError):
            await aws_backend._get_aws_identity(None)
