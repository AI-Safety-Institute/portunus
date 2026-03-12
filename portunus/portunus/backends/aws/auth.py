"""AWS authentication backend.

Implements AuthBackend using AWS STS for identity, Secrets Manager for
API key retrieval, and KMS for optional request signing.
"""

import logging
from typing import Optional

from aiobotocore.session import get_session
from botocore.exceptions import ClientError

from portunus.backends.aws.identity import parse_identity_from_arn
from portunus.config import config
from portunus.exceptions import (
    CredentialsError,
    FetchSecretError,
    PayloadError,
)
from portunus.models import (
    AuthPayload,
    AuthResult,
    AwsCredentials,
    PrincipalInfo,
)
from portunus.services.secret_validation_service import (
    SecretValidationService,
)
from portunus.services.signing_service import (
    SignableRequest,
    SignatureHeaders,
    sign_request,
)

logger = logging.getLogger("api.access")


class AwsAuthBackend:
    """AWS-backed authentication using STS, Secrets Manager, and KMS.

    This backend:
    - Decodes a base64 payload containing AWS credentials + secret ARN
    - Calls STS get_caller_identity to resolve the caller
    - Parses the ARN with a configurable role pattern for project extraction
    - Fetches the API key from Secrets Manager
    - Optionally signs requests via KMS
    """

    def __init__(
        self,
        role_pattern: str | None = None,
        validation_service: SecretValidationService | None = None,
    ):
        self.boto_session = get_session()
        self.role_pattern = role_pattern
        self.validation_service = validation_service or SecretValidationService()

    async def authenticate(
        self,
        raw_payload: str,
        request_id: str,
        target_host: str | None = None,
    ) -> AuthResult:
        """Decode payload, verify identity via STS, fetch secret."""
        try:
            payload = AuthPayload.from_contents(raw_payload, target_host=None)
        except Exception as e:
            raise PayloadError(f"Failed to decode authorization payload: {e}") from e

        credentials = payload.credentials

        # Get caller identity from AWS STS
        principal_info = await self._get_aws_identity(credentials)

        # Fetch raw secret from Secrets Manager
        raw_secret = await self._fetch_secret(payload)

        # Validate and extract API key
        api_key, signing_key = self.validation_service.validate_and_extract_api_key(
            raw_secret, target_host
        )

        return AuthResult(
            api_key=api_key,
            signing_key=signing_key,
            principal_info=principal_info,
        )

    async def sign_request(
        self,
        raw_payload: str,
        signable_request: SignableRequest,
        auth_result: AuthResult,
    ) -> SignatureHeaders | None:
        """Sign a request using KMS with the caller's AWS credentials."""
        if auth_result.signing_key is None:
            return None

        try:
            payload = AuthPayload.from_contents(raw_payload, target_host=None)
        except Exception:
            return None

        return sign_request(
            signable_request,
            auth_result.signing_key,
            auth_result.api_key,
            payload.credentials,
        )

    async def _get_aws_identity(
        self, credentials: Optional[AwsCredentials] = None
    ) -> PrincipalInfo:
        """Get caller identity from AWS STS and parse the ARN."""
        if not credentials or not credentials.is_valid():
            raise CredentialsError(
                "Valid AWS credentials are required for authentication"
            )

        try:
            async with self.boto_session.create_client(
                "sts",
                aws_access_key_id=credentials.access_key_id,
                aws_secret_access_key=credentials.secret_access_key,
                aws_session_token=credentials.session_token,
                endpoint_url=config.aws.endpoint_url,
            ) as sts_client:
                response = await sts_client.get_caller_identity()
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ExpiredToken":
                logger.info(f"Credentials expired when calling STS: {e}")
                raise CredentialsError("AWS credentials have expired") from e
            logger.error(f"STS client error: {e}")
            raise CredentialsError(
                "Failed to get caller identity with provided" " credentials"
            ) from e
        except Exception as e:
            logger.error(f"Failed to create STS client: {e}")
            raise CredentialsError(
                "Failed to create STS client with provided" " credentials"
            ) from e

        principal_arn = response.get("Arn", "")
        return parse_identity_from_arn(principal_arn, self.role_pattern)

    async def _fetch_secret(self, payload: AuthPayload) -> str:
        """Fetch raw secret from AWS Secrets Manager."""
        try:
            async with self.boto_session.create_client(
                "secretsmanager",
                aws_access_key_id=(payload.credentials.access_key_id),
                aws_secret_access_key=(payload.credentials.secret_access_key),
                aws_session_token=(payload.credentials.session_token),
                endpoint_url=config.aws.endpoint_url,
            ) as client:
                response = await client.get_secret_value(SecretId=payload.secret_arn)
                return response["SecretString"]
        except Exception as e:
            logger.error(f"Failed to get secret from Secrets Manager: {e}")
            raise FetchSecretError(
                403,
                f"Failed to get secret from Secrets Manager: {e}",
            ) from e
