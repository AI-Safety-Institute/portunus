"""
Authentication service module.

This module contains the AuthService class, which is responsible for handling
authentication-related operations such as validating credentials, retrieving
API keys, and managing principal identities.
"""

import asyncio
import logging
from typing import Optional

from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError

from portunus.config import config
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    PayloadError,
)
from portunus.models import (
    AuthPayload,
    AuthResult,
    AwsCredentials,
    PrincipalInfo,
)
from portunus.services.arn_service import parse_identity_from_arn
from portunus.services.cache_service import CacheService
from portunus.services.secret_validation_service import SecretValidationService
from portunus.services.secrets_service import SecretsService
from portunus.services.team_service import TeamService

logger = logging.getLogger("api.access")


class AuthService:
    """
    Service for handling authentication operations.

    This service is responsible for processing authentication requests,
    validating credentials, and retrieving API keys from the appropriate
    source (cache or Secrets Manager).

    Attributes:
        secrets_service: SecretsService for retrieving API keys
        cache_service: CacheService for caching authentication results
    """

    def __init__(
        self,
        secrets_service: Optional[SecretsService] = None,
        cache_service: Optional[CacheService] = None,
        validation_service: Optional[SecretValidationService] = None,
        team_service: Optional[TeamService] = None,
    ):
        """Initialize the AuthService."""
        self.secrets_service = secrets_service or SecretsService()
        self.cache_service = cache_service or CacheService()
        self.validation_service = validation_service or SecretValidationService()
        # Team resolution is only used when team stamping is enabled; share the
        # auth cache_service so the roleArn->teams cache lives in the same Redis.
        self.team_service = team_service or TeamService(
            cache_service=self.cache_service
        )
        self.boto_session = self.secrets_service.boto_session

    @xray_recorder.capture_async()  # type: ignore
    async def get_aws_identity(
        self, credentials: Optional[AwsCredentials] = None
    ) -> PrincipalInfo:
        """
        Get AWS caller identity information using the provided credentials.

        Args:
            credentials: AWS credentials containing access_key_id, secret_access_key,
                       and session_token.

        Returns:
            PrincipalInfo object containing the caller's identity information

        Raises:
            CredentialsError: When credentials are missing, invalid, or expired.
        """
        # Check if credentials are valid
        if not credentials or not credentials.is_valid():
            raise CredentialsError(
                "Valid AWS credentials are required for authentication"
            )

        # Create STS client with the provided credentials
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
            # https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_Errors
            if error_code == "ExpiredToken":
                logger.info(f"Credentials expired when calling STS: {e}")
                raise CredentialsError("AWS credentials have expired") from e
            logger.error(f"STS client error: {e}")
            raise CredentialsError(
                "Failed to get caller identity with provided credentials"
            ) from e
        except Exception as e:
            # If client creation fails, raise an error
            logger.error(f"Failed to create STS client: {e}")
            raise CredentialsError(
                "Failed to create STS client with provided credentials"
            ) from e

        # Extract the ARN and parse it
        principal_arn = response.get("Arn", "")

        # Parse the ARN to get identity information
        return parse_identity_from_arn(principal_arn)

    @xray_recorder.capture_async()  # type: ignore
    async def authenticate(
        self, payload: AuthPayload, request_id: str, target_host: Optional[str] = None
    ) -> AuthResult:
        """
        Authenticate a request using the provided payload.

        This method implements a two-level caching strategy:
        1. First check Redis cache using the raw payload as key
        2. If not in cache, decode payload, retrieve from AWS, and cache result

        The cache TTL is set to the credential expiration time to ensure
        cached results don't outlive the credentials they were retrieved with.

        Args:
            payload: The parsed base64-encoded payload from authorization header
            request_id: The unique request ID for logging and correlation
            target_host: Optional target host from the proxy for validation

        Returns:
            AuthResult containing:
            - API key
            - signing key (if required for this lab / model)
            - principal information

        Raises:
            PayloadError: If the payload cannot be decoded
            CredentialsError: If the AWS credentials are invalid or expired
            AuthenticationError: If there's an error during authentication
        """
        # Check cache first for better performance
        if payload.raw:
            try:
                async with asyncio.timeout(5):
                    cached_result = await self.cache_service.get_cached_auth_result(
                        payload.raw
                    )
                    if cached_result:
                        return AuthResult(
                            api_key=cached_result.api_key,
                            signing_key=cached_result.signing_key,
                            principal_info=cached_result.principal_info,
                        )
            except Exception as e:
                logger.error(f"Cache read error during auth: {e}")

        # If not in cache, proceed with full authentication
        try:
            credentials = payload.credentials

            # Get caller identity from AWS STS
            principal_info = await self.get_aws_identity(credentials)

            # Resolve + stamp live team attribution (logging metadata only).
            # Gated behind a feature flag (default off): when disabled the hot
            # path is unchanged and no extra IAM call is made. When enabled,
            # resolution is best-effort and never blocks, denies, or errors the
            # request - on any failure principal_info.teams is the sentinel.
            if config.team_stamping_enabled:
                principal_info.teams = await self.team_service.resolve_teams(
                    credentials, principal_info.arn
                )

            # Retrieve raw secret from Secrets Manager
            raw_secret = await self.secrets_service.fetch_secret(payload)

            # Validate and extract API key
            api_key, signing_key = self.validation_service.validate_and_extract_api_key(
                raw_secret, target_host
            )

            # Create auth result
            auth_result = AuthResult(
                api_key=api_key, signing_key=signing_key, principal_info=principal_info
            )

            # Cache the results for future requests (best effort)
            # Use credential expiration as TTL so cache doesn't outlive credentials
            if payload.raw and auth_result.successful:
                try:
                    # Store in Redis cache for fast retrieval
                    async with asyncio.timeout(3):
                        ttl = credentials.seconds_until_expiration()
                        await self.cache_service.cache_auth_result(
                            payload.raw, auth_result, ttl
                        )
                except Exception as e:
                    logger.error(f"Cache write error during auth: {e}")

            return auth_result
        except (PayloadError, CredentialsError):
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")
