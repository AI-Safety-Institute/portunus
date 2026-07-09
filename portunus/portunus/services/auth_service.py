"""
Authentication service module.

This module contains the AuthService class, which is responsible for handling
authentication-related operations such as validating credentials, retrieving
API keys, and managing principal identities.
"""

import asyncio
import logging
from typing import Optional

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
    SecretsManagerAuthPayload,
    SigningKey,
)
from portunus.services.arn_service import parse_identity_from_arn
from portunus.services.cache_service import CacheService, normalise_target_host
from portunus.services.secrets_service import SecretsService
from portunus.services.state_service import StateService

logger = logging.getLogger("api.access")


def validate_and_extract_api_key(
    secret_string: str, target_host: str | None
) -> tuple[str, Optional[SigningKey]]:
    """Parse a Secrets Manager secret and enforce its host restriction.

    Plaintext secrets pass through with no validation. JSON secrets that
    declare a ``host`` field are gated: the proxy-supplied ``target_host``
    must match the secret's host, otherwise raises
    :class:`AuthenticationError`. Both sides are canonicalised with
    :func:`normalise_target_host` (lower-case, default ``:443`` stripped)
    before comparison — the SAME normalisation
    ``CacheService.generate_cache_key`` applies, so the set of hosts a
    cache hit admits is exactly the set this fail-closed miss-path check
    accepts. Any non-equivalent host still fails closed.

    Returns ``(api_key, signing_key)`` — ``signing_key`` is set only for
    request-signing tenants.
    """
    secret = SecretsManagerAuthPayload.from_string(secret_string)
    if secret.host:
        if not target_host:
            logger.warning(f"Secret has host ({secret.host}) but proxy sent no target")
            raise AuthenticationError(
                "API key has host restriction but target host unknown"
            )
        if normalise_target_host(target_host) != normalise_target_host(secret.host):
            logger.warning(f"Host mismatch: proxy={target_host}, secret={secret.host}")
            raise AuthenticationError("API key is not valid for target host")
        logger.info(f"Target host validation passed for {target_host}")
    else:
        logger.info("Secret has no host restriction, skipping validation")
    return secret.api_key, secret.signing_key


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
    ):
        """Initialize the AuthService.

        When no ``secrets_service`` is injected and the cache service is
        backed by a real :class:`StateService`, the default
        :class:`SecretsService` (and this service's own STS calls, which
        share its ``boto_session``) use the StateService's pooled boto
        session: AWS clients are then created once per (service, credential
        set) and reused, instead of paying a fresh aiohttp pool + TLS
        handshake (~200ms cold, twice) on every auth cache-miss.
        """
        self.cache_service = cache_service or CacheService()
        if secrets_service is None:
            state_service = getattr(self.cache_service, "state_service", None)
            if isinstance(state_service, StateService):
                secrets_service = SecretsService(
                    boto_session=state_service.pooled_boto_session()
                )
            else:
                secrets_service = SecretsService()
        self.secrets_service = secrets_service
        self.boto_session = self.secrets_service.boto_session

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
                logger.info(
                    "Credentials expired when calling STS (Code=%s)", error_code
                )
                raise CredentialsError("AWS credentials have expired") from e
            # Boto exception __str__ can carry header fragments under
            # certain error codes — log the Code only.
            logger.error("STS client error (Code=%s)", error_code or type(e).__name__)
            raise CredentialsError(
                "Failed to get caller identity with provided credentials"
            ) from e
        except Exception as e:
            logger.error("Failed to create STS client: %s", type(e).__name__)
            raise CredentialsError(
                "Failed to create STS client with provided credentials"
            ) from e

        # Extract the ARN and parse it
        principal_arn = response.get("Arn", "")

        # Parse the ARN to get identity information
        return parse_identity_from_arn(principal_arn)

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
        # Check cache first for better performance. target_host MUST be
        # part of the lookup key — without it a cache hit short-circuits
        # SecretValidationService.validate_and_extract_api_key, which is
        # where the secret's host-restriction is enforced.
        if payload.raw:
            try:
                async with asyncio.timeout(5):
                    cached_result = await self.cache_service.get_cached_auth_result(
                        payload.raw, target_host
                    )
                    if cached_result:
                        return AuthResult(
                            api_key=cached_result.api_key,
                            signing_key=cached_result.signing_key,
                            principal_info=cached_result.principal_info,
                        )
            except Exception as e:
                logger.error("Cache read error during auth: %s", type(e).__name__)

        # If not in cache, proceed with full authentication
        try:
            credentials = payload.credentials

            # Get caller identity from AWS STS
            principal_info = await self.get_aws_identity(credentials)

            # Retrieve raw secret from Secrets Manager
            raw_secret = await self.secrets_service.fetch_secret(payload)

            # Validate and extract API key
            api_key, signing_key = validate_and_extract_api_key(raw_secret, target_host)

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
                            payload.raw, auth_result, ttl, target_host
                        )
                except Exception as e:
                    logger.error("Cache write error during auth: %s", type(e).__name__)

            return auth_result
        except (PayloadError, CredentialsError, AuthenticationError):
            # Own exception types — message is curated by us, surface as-is
            # so callers (and clients via _denied) see the actual reason
            # (e.g. "API key is not valid for target host").
            raise
        except Exception as e:
            logger.error("Authentication error: %s", type(e).__name__)
            raise AuthenticationError(f"Authentication failed: {type(e).__name__}")
