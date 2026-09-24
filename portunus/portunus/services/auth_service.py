"""
Authentication service module.

This module contains the AuthService class, which is responsible for handling
authentication-related operations such as validating credentials, retrieving
API keys, and managing principal identities.
"""

import asyncio
import logging
import time
from typing import Optional

from botocore.exceptions import ClientError
from redis.exceptions import TimeoutError as RedisTimeoutError

from portunus.config import config
from portunus.exceptions import (
    AuthenticationError,
    AuthOverloadedError,
    CredentialsError,
    PayloadError,
)
from portunus.metrics import (
    AUTH_REDIS_ERROR,
    AUTH_REDIS_HIT,
    AUTH_REDIS_MISS,
    FULL_AUTH,
    FULL_AUTH_LATENCY,
    FULL_AUTH_SHED,
    metrics,
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
from portunus.services.cache_service import (
    CacheService,
    auth_cache_key,
    normalise_target_host,
)
from portunus.services.local_auth_cache import LocalAuthCache
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
        local_cache: Optional[LocalAuthCache] = None,
    ):
        """Initialize the AuthService.

        When no ``secrets_service`` is injected and the cache service is
        backed by a real :class:`StateService`, the default
        :class:`SecretsService` (and this service's own STS calls, which
        share its ``boto_session``) use the StateService's pooled boto
        session: AWS clients are then created once per (service, credential
        set) and reused, instead of paying a fresh aiohttp pool + TLS
        handshake (~200ms cold, twice) on every auth cache-miss.

        ``local_cache`` defaults to a :class:`LocalAuthCache` sized from
        ``config.auth_cache``; pass one with ``ttl_seconds=0`` to disable it.
        """
        # ``is None``, not ``or``: an empty LocalAuthCache is falsy (__len__).
        if local_cache is None:
            local_cache = LocalAuthCache(
                ttl_seconds=config.auth_cache.local_ttl_seconds,
                stale_seconds=config.auth_cache.local_stale_seconds,
                max_entries=config.auth_cache.local_max_entries,
            )
        self.local_cache = local_cache
        self._fallback_slots = asyncio.Semaphore(
            config.auth_cache.fallback_max_concurrent
        )
        self._fallback_acquire_timeout_s = config.auth_cache.fallback_acquire_timeout_s
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

        Three tiers, cheapest first:
        1. The in-process L1 cache (:class:`LocalAuthCache`), no I/O.
        2. Redis, keyed on the raw payload and target host. Concurrent L1
           misses for one key share a single Redis read (single-flight).
        3. Full authentication: decode payload, STS + Secrets Manager, then
           write back to Redis and L1.

        Cache TTLs are bounded by the credential expiration so cached results
        never outlive the credentials they were retrieved with.

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
            TimeoutError: If the cache read times out and L1 holds no stale
                entry; the request is rejected rather than falling back to
                STS and Secrets Manager
        """
        if not payload.raw or not self.local_cache.enabled:
            return await self._authenticate_via_redis(
                payload, request_id, target_host, key=None
            )
        # target_host MUST be part of the key — without it a cache hit
        # short-circuits validate_and_extract_api_key, which is where the
        # secret's host-restriction is enforced. Same key as Redis.
        key = auth_cache_key(payload.raw, target_host)
        return await self.local_cache.get_or_load(
            key,
            lambda: self._authenticate_via_redis(
                payload, request_id, target_host, key=key
            ),
        )

    def has_servable_cache_entries(self) -> bool:
        """Whether L1 could answer some requests without Redis right now."""
        return self.local_cache.has_servable_entries()

    async def _authenticate_via_redis(
        self,
        payload: AuthPayload,
        request_id: str,
        target_host: Optional[str],
        *,
        key: Optional[str],
    ) -> AuthResult:
        """Redis lookup, then full authentication; fills L1 when ``key`` is set.

        On a Redis failure a stale L1 entry (still inside the credential
        expiry) is served instead of rejecting or falling back to STS.
        """
        if payload.raw:
            try:
                async with asyncio.timeout(5):
                    cached_result = await self.cache_service.get_cached_auth_result(
                        payload.raw, target_host
                    )
                    if cached_result:
                        metrics.incr(AUTH_REDIS_HIT)
                        result = AuthResult(
                            api_key=cached_result.api_key,
                            signing_key=cached_result.signing_key,
                            principal_info=cached_result.principal_info,
                        )
                        self._remember(key, result, payload)
                        return result
                    metrics.incr(AUTH_REDIS_MISS)
            except (TimeoutError, RedisTimeoutError) as e:
                metrics.incr(AUTH_REDIS_ERROR)
                stale = self._stale(key)
                if stale is not None:
                    logger.warning(
                        "Cache read timed out during auth for %s (%s); serving "
                        "stale in-process entry",
                        request_id,
                        type(e).__name__,
                    )
                    return stale
                logger.warning(
                    f"Cache read timed out during auth for {request_id} "
                    f"({type(e).__name__}); rejecting rather than falling back to "
                    "full authentication"
                )
                raise TimeoutError("Cache read timed out during authentication") from e
            except Exception as e:
                metrics.incr(AUTH_REDIS_ERROR)
                stale = self._stale(key)
                if stale is not None:
                    logger.warning(
                        "Cache read error during auth (%s); serving stale "
                        "in-process entry",
                        type(e).__name__,
                    )
                    return stale
                logger.error("Cache read error during auth: %s", type(e).__name__)

        auth_result = await self._bounded_full_authenticate(
            payload, request_id, target_host
        )
        self._remember(key, auth_result, payload)
        return auth_result

    async def _bounded_full_authenticate(
        self, payload: AuthPayload, request_id: str, target_host: Optional[str]
    ) -> AuthResult:
        """Run full authentication under the per-process concurrency cap.

        When Redis wobbles every miss lands here; unbounded, that is one STS
        and one Secrets Manager call per distinct key per task at once, which
        is what throttled STS and turned a Redis blip into a 403 storm. Past
        the cap requests are shed with :class:`AuthOverloadedError` (503).
        """
        try:
            async with asyncio.timeout(self._fallback_acquire_timeout_s):
                await self._fallback_slots.acquire()
        except TimeoutError:
            metrics.incr(FULL_AUTH_SHED)
            logger.warning(
                "Full-auth capacity exhausted; shedding (request_id=%s)", request_id
            )
            raise AuthOverloadedError() from None
        metrics.incr(FULL_AUTH)
        started = time.perf_counter()
        try:
            return await self._full_authenticate(payload, target_host)
        finally:
            # Timed whatever the outcome: a slow FAILING STS is exactly the
            # case the latency series has to show.
            metrics.observe(FULL_AUTH_LATENCY, (time.perf_counter() - started) * 1000)
            self._fallback_slots.release()

    def _remember(
        self, key: Optional[str], result: AuthResult, payload: AuthPayload
    ) -> None:
        if key is None:
            return
        credentials = payload.credentials
        ttl = credentials.seconds_until_expiration() if credentials else None
        self.local_cache.put(key, result, ttl)

    def _stale(self, key: Optional[str]) -> Optional[AuthResult]:
        return self.local_cache.get_stale(key) if key is not None else None

    async def _full_authenticate(
        self, payload: AuthPayload, target_host: Optional[str]
    ) -> AuthResult:
        """STS + Secrets Manager, then best-effort write-back to Redis."""
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
