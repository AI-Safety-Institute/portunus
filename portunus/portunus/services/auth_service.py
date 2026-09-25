"""
Authentication service module.

This module contains the AuthService class, which is responsible for handling
authentication-related operations such as validating credentials, retrieving
API keys, and managing principal identities.
"""

import asyncio
import logging
import weakref
from typing import Optional

from botocore.exceptions import ClientError
from redis.exceptions import TimeoutError as RedisTimeoutError

from portunus.config import config
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    PayloadError,
    ServiceError,
)
from portunus.models import (
    AuthPayload,
    AuthResult,
    AwsCredentials,
    MintSecretBase,
    PrincipalInfo,
)
from portunus.services.arn_service import parse_identity_from_arn
from portunus.services.cache_service import CacheService, effective_cache_ttl
from portunus.services.federation_service import TokenMintService
from portunus.services.secret_validation_service import SecretValidationService
from portunus.services.secrets_service import SecretsService
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

# Minted tokens are always sent as an OAuth bearer credential.
MINTED_TOKEN_HEADER = "authorization"
MINTED_TOKEN_PREFIX = "Bearer "


class AuthService:
    """
    Service for handling authentication operations.

    This service is responsible for processing authentication requests,
    validating credentials, and retrieving API keys from the appropriate
    source (cache, Secrets Manager, or a provider token endpoint).

    Attributes:
        secrets_service: SecretsService for retrieving API keys
        cache_service: CacheService for caching authentication results
        validation_service: Parses secrets and enforces host restrictions
        mint_service: Mints short-lived tokens for federation secrets
    """

    def __init__(
        self,
        secrets_service: Optional[SecretsService] = None,
        cache_service: Optional[CacheService] = None,
        validation_service: Optional[SecretValidationService] = None,
        mint_service: Optional[TokenMintService] = None,
    ):
        """Initialize the AuthService."""
        self.secrets_service = secrets_service or SecretsService()
        self.cache_service = cache_service or CacheService()
        self.validation_service = validation_service or SecretValidationService()
        self.boto_session = self.secrets_service.boto_session
        self.mint_service = mint_service or TokenMintService(
            boto_session=self.boto_session
        )
        # Per-process single flight for minting: concurrent cache misses on
        # one payload and target wait for a single mint instead of each
        # calling STS and the provider. A lock is dropped once no coroutine
        # holds it.
        self._mint_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    @capture_async()
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

    @capture_async()
    async def authenticate(
        self, payload: AuthPayload, request_id: str, target_host: Optional[str] = None
    ) -> AuthResult:
        """
        Authenticate a request using the provided payload.

        Checks the Redis cache first (keyed by the raw payload and the target
        host). On a miss it verifies the caller with STS, fetches and parses
        the secret, and either returns the stored key or mints a short-lived
        token as the secret describes. Stored keys are cached for the
        configured cache duration; minted tokens for no longer than the token
        remains valid.

        Args:
            payload: The parsed base64-encoded payload from authorization header
            request_id: The unique request ID for logging and correlation
            target_host: Optional target host from the proxy; part of the cache
                key and checked against the secret's host restriction

        Returns:
            AuthResult containing:
            - API key (stored key or minted token)
            - principal information
            - upstream header and prefix, when the secret dictates them

        Raises:
            PayloadError: If the payload cannot be decoded
            CredentialsError: If the AWS credentials are invalid or expired
            ServiceError: If a dependency failed (``FetchSecretError``,
                ``UpstreamServiceError``) or the service is misconfigured
            AuthenticationError: If there's an error during authentication
            TimeoutError: If the cache read times out; the request is rejected
                rather than falling back to STS and Secrets Manager
        """
        cached_result = await self._read_cache(payload, target_host)
        if cached_result:
            return cached_result

        try:
            credentials = payload.credentials

            # Get caller identity from AWS STS
            principal_info = await self.get_aws_identity(credentials)

            # Retrieve and parse the secret from Secrets Manager
            raw_secret = await self.secrets_service.fetch_secret(payload)
            secret = self.validation_service.validate_secret(raw_secret, target_host)

            if isinstance(secret, MintSecretBase):
                return await self._authenticate_with_minted_token(
                    payload, target_host, principal_info, secret
                )

            auth_result = AuthResult(
                api_key=secret.api_key, principal_info=principal_info
            )
            await self._write_cache(payload, target_host, auth_result)
            return auth_result
        except (PayloadError, CredentialsError, ServiceError, TimeoutError):
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")

    async def _authenticate_with_minted_token(
        self,
        payload: AuthPayload,
        target_host: Optional[str],
        principal_info: PrincipalInfo,
        secret: MintSecretBase,
    ) -> AuthResult:
        async with self._mint_lock(payload, target_host):
            # A concurrent request for the same payload and target may have
            # minted and cached a token while this one waited for the lock.
            cached_result = await self._read_cache(payload, target_host)
            if cached_result:
                return cached_result

            minted = await self.mint_service.mint(
                payload.credentials, principal_info, secret
            )
            auth_result = AuthResult(
                api_key=minted.token,
                principal_info=principal_info,
                output_header=MINTED_TOKEN_HEADER,
                output_prefix=MINTED_TOKEN_PREFIX,
                expires_at=minted.expires_at,
                identity_token_id=minted.identity_token_id,
                attribution_handle=minted.attribution_handle,
            )
            await self._write_cache(payload, target_host, auth_result)
            return auth_result

    def _mint_lock(
        self, payload: AuthPayload, target_host: Optional[str]
    ) -> asyncio.Lock:
        key = self.cache_service.generate_cache_key(payload.raw, target_host)
        lock = self._mint_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._mint_locks[key] = lock
        return lock

    async def _read_cache(
        self, payload: AuthPayload, target_host: Optional[str]
    ) -> Optional[AuthResult]:
        """Best-effort cache lookup.

        Errors are logged and treated as a miss, except a timeout, which is
        raised so the request is rejected instead of falling back to STS and
        Secrets Manager.
        """
        if not payload.raw:
            return None
        try:
            async with asyncio.timeout(5):
                return await self.cache_service.get_cached_auth_result(
                    payload.raw, target_host
                )
        except (TimeoutError, RedisTimeoutError) as e:
            logger.warning(
                f"Cache read timed out during auth ({type(e).__name__}); rejecting "
                "rather than falling back to full authentication"
            )
            raise TimeoutError("Cache read timed out during authentication") from e
        except Exception as e:
            logger.error(f"Cache read error during auth: {type(e).__name__}: {e}")
            return None

    async def _write_cache(
        self,
        payload: AuthPayload,
        target_host: Optional[str],
        auth_result: AuthResult,
    ) -> None:
        """Best-effort cache write."""
        if not (payload.raw and auth_result.successful):
            return
        try:
            async with asyncio.timeout(3):
                if auth_result.expires_at is None:
                    ttl = payload.credentials.seconds_until_expiration()
                else:
                    ttl = effective_cache_ttl(
                        cache_duration=self.cache_service.cache_duration,
                        token_expires_at=auth_result.expires_at,
                    )
                await self.cache_service.cache_auth_result(
                    payload.raw, target_host, auth_result, ttl
                )
        except Exception as e:
            logger.error(f"Cache write error during auth: {e}")
