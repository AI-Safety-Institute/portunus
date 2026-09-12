"""
API authentication response caching service module.

This module contains the CacheService class, which is responsible for caching
and retrieving authentication responses in Redis.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from portunus.config import config
from portunus.exceptions import CacheError
from portunus.models import AuthResult, PrincipalInfo, SigningKey
from portunus.services.state_service import StateService
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

# Minted tokens leave the cache this long before they expire, so a cached
# token is never handed out with only seconds of validity left.
TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS = 300


def effective_cache_ttl(
    *,
    cache_duration: int,
    credential_expiry_seconds: Optional[int],
    token_expires_at: Optional[datetime],
    now: Optional[datetime] = None,
) -> int:
    """Seconds a cached auth result may live.

    The smallest of the configured cache duration, the caller's remaining
    credential lifetime, and (for minted tokens) the token lifetime less
    ``TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS``. Never negative; 0 means do not
    cache.

    Args:
        cache_duration: Configured maximum TTL
        credential_expiry_seconds: Seconds until the caller's credentials
            expire, or None when the payload carries no expiration
        token_expires_at: When a minted token expires, or None for stored keys
        now: Reference time (defaults to the current UTC time)
    """
    candidates = [cache_duration]
    if credential_expiry_seconds is not None:
        candidates.append(credential_expiry_seconds)
    if token_expires_at is not None:
        remaining = token_expires_at - (now or datetime.now(timezone.utc))
        candidates.append(
            int(remaining.total_seconds()) - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS
        )
    return max(0, min(candidates))


class CacheService:
    """
    Service for caching and retrieving authentication responses.

    This service is responsible for managing the caching of authentication
    responses, including API keys and principal information, in Redis.

    Attributes:
        state_service: The service providing access to Redis
        cache_duration: How long to cache entries (in seconds)
    """

    def __init__(self, state_service: Optional[StateService] = None):
        """Initialize the CacheService."""
        self.state_service = state_service or StateService()
        self.cache_duration = config.redis.cache_duration

    def generate_cache_key(self, payload: str) -> str:
        """
        Generate a secure cache key from a payload.

        Creates a SHA-256 hash of the payload to use as a Redis key,
        ensuring keys are of consistent length and don't contain
        sensitive information.

        Args:
            payload: The payload to use for the cache key.

        Returns:
            A hash of the payload to use as a cache key.
        """
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def get_cached_auth_result(self, payload: str) -> Optional[AuthResult]:
        """
        Get an authentication result from the cache.

        Args:
            payload: The payload used as a lookup key.

        Returns:
            AuthResult if found, None otherwise. Entries written before
            output_header/output_prefix existed load with both set to None.

        Raises:
            CacheError: If there's an error accessing the cache.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache lookup")
            return None

        try:
            cache_key = self.generate_cache_key(payload)
            cached_data = await client.get(cache_key)

            if cached_data:
                logger.info(f"Cache hit for key {cache_key[:8]}...")
                auth_response = json.loads(cached_data)

                principal_info = PrincipalInfo.from_dict(
                    auth_response["principal_info"]
                )

                signing_key_data = auth_response.get("signing_key")
                signing_key = (
                    SigningKey(
                        provider_id=signing_key_data["provider_id"],
                        kms_key_arn=signing_key_data["kms_key_arn"],
                    )
                    if signing_key_data is not None
                    else None
                )

                expires_at = auth_response.get("expires_at")
                return AuthResult(
                    api_key=auth_response["api_key"],
                    signing_key=signing_key,
                    principal_info=principal_info,
                    output_header=auth_response.get("output_header"),
                    output_prefix=auth_response.get("output_prefix"),
                    expires_at=(
                        datetime.fromisoformat(expires_at) if expires_at else None
                    ),
                )

            logger.info(f"Cache miss for key {cache_key[:8]}...")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding cached data: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting from cache: {e}")
            raise CacheError(f"Failed to retrieve from cache: {e}")

    async def cache_auth_response(
        self,
        payload: str,
        api_key: str,
        signing_key: Optional[SigningKey],
        principal_info: PrincipalInfo,
        ttl_seconds: Optional[int] = None,
        output_header: Optional[str] = None,
        output_prefix: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """
        Cache an authentication response including API key and principal info.

        Args:
            payload: The payload to use as a cache key.
            api_key: The API key to cache.
            signing_key: The request signing key details for this api key.
            principal_info: Principal information to cache and log.
            ttl_seconds: Optional TTL override
            output_header: Upstream header that should carry the credential
            output_prefix: Prefix for the credential value
            expires_at: When a minted credential expires

        Returns:
            True if successfully cached, False otherwise.

        Raises:
            CacheError: If there's an error storing in the cache.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for caching")
            return False

        try:
            cache_key = self.generate_cache_key(payload)
            effective_ttl = (
                ttl_seconds if ttl_seconds is not None else self.cache_duration
            )

            # Skip caching if TTL is 0 or negative (credentials already expired)
            if effective_ttl <= 0:
                logger.info(
                    f"Skipping cache for principal {principal_info.arn}: "
                    f"TTL is {effective_ttl}s"
                )
                return False

            # Store both API key and principal info as JSON
            principal_info_dict = principal_info.to_dict()
            auth_response = {
                "api_key": api_key,
                "principal_info": principal_info_dict,
                "signing_key": signing_key.to_dict() if signing_key else None,
                "output_header": output_header,
                "output_prefix": output_prefix,
                "expires_at": expires_at.isoformat() if expires_at else None,
            }

            result = await client.setex(
                cache_key, effective_ttl, json.dumps(auth_response)
            )

            logger.info(
                f"Cached auth response for principal: "
                f"{principal_info.arn}, "
                f"expires in {effective_ttl}s)"
            )

            return bool(result)
        except Exception as e:
            logger.error(f"Error caching auth response: {e}")
            raise CacheError(f"Failed to store in cache: {e}")

    @capture_async()
    async def cache_auth_result(
        self,
        payload: str,
        auth_result: AuthResult,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """
        Cache an authentication result.

        Args:
            payload: The payload to use as a cache key.
            auth_result: The authentication result to cache.
            ttl_seconds: Optional TTL override based on credential expiration.

        Returns:
            True if successfully cached, False otherwise.
        """
        return await self.cache_auth_response(
            payload,
            auth_result.api_key,
            auth_result.signing_key,
            auth_result.principal_info,
            ttl_seconds,
            output_header=auth_result.output_header,
            output_prefix=auth_result.output_prefix,
            expires_at=auth_result.expires_at,
        )

    @capture_async()
    async def cache_api_key(
        self,
        payload: str,
        api_key: str,
        signing_key: Optional[SigningKey],
        principal_info: PrincipalInfo,
    ) -> bool:
        """
        Cache an API key and principal info.

        Args:
            payload: The payload to use as a cache key.
            api_key: The API key to cache.
            signing_key: The request signing key details for this api key.
            principal_info: Principal information to cache and log.

        Returns:
            True if successfully cached, False otherwise.
        """
        return await self.cache_auth_response(
            payload, api_key, signing_key, principal_info
        )

    @capture_async()
    async def invalidate_cache_entry(self, payload: str) -> bool:
        """
        Invalidate a cache entry.

        Args:
            payload: The payload whose cache entry should be invalidated.

        Returns:
            True if successfully invalidated or entry didn't exist, False on error.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache invalidation")
            return False

        try:
            cache_key = self.generate_cache_key(payload)
            await client.delete(cache_key)
            logger.info(f"Invalidated cache key {cache_key[:8]}...")
            return True
        except Exception as e:
            logger.error(f"Error invalidating cache entry: {e}")
            return False

    @capture_async()
    async def flush_all(self) -> bool:
        """
        Flush the entire auth cache.

        Returns:
            True if successfully flushed, False on error.

        Raises:
            CacheError: If there's an error flushing the cache.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache flush")
            return False

        try:
            await client.flushdb()
            logger.info("Flushed all auth cache entries")
            return True
        except Exception as e:
            logger.error(f"Error flushing cache: {e}")
            raise CacheError(f"Failed to flush cache: {e}")

    @capture_async()
    async def health_check(self) -> bool:
        """
        Check if Redis cache is available.

        Returns:
            True if Redis is available, False otherwise.
        """
        return await self.state_service.health_check()
