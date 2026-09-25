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

from redis.exceptions import TimeoutError as RedisTimeoutError

from portunus.config import config
from portunus.exceptions import CacheError
from portunus.models import AuthResult, PrincipalInfo
from portunus.services.state_service import StateService
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

# Minted tokens leave the cache this long before they expire. Auth is checked
# when a request begins, not for its duration, so the margin only has to cover
# clock skew and the latency between authorisation and the request reaching
# the provider.
TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS = 60


def effective_cache_ttl(
    *,
    cache_duration: int,
    token_expires_at: datetime,
    now: Optional[datetime] = None,
) -> int:
    """Seconds a minted token may stay cached.

    The configured cache duration, or the token's lifetime less
    ``TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS`` if that is shorter. Never negative;
    0 means do not cache.

    Args:
        cache_duration: Configured maximum TTL
        token_expires_at: When the token expires
        now: Reference time (defaults to the current UTC time)
    """
    remaining = token_expires_at - (now or datetime.now(timezone.utc))
    token_ttl = int(remaining.total_seconds()) - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS
    return max(0, min(cache_duration, token_ttl))


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

    def generate_cache_key(self, payload: str, target_host: Optional[str]) -> str:
        """
        Generate a secure cache key from a payload and its target host.

        Creates a SHA-256 hash over the payload and the target host to use
        as a Redis key, so keys are of consistent length, don't contain
        sensitive information, and a result authorised for one proxy's
        upstream is never a hit for a proxy with a different one.

        Args:
            payload: The payload to use for the cache key.
            target_host: The proxy's target host, or None when it sent none.

        Returns:
            A hash of the payload and target host to use as a cache key.
        """
        return hashlib.sha256(
            f"{payload}\n{target_host or ''}".encode("utf-8")
        ).hexdigest()

    async def get_cached_auth_result(
        self, payload: str, target_host: Optional[str]
    ) -> Optional[AuthResult]:
        """
        Get an authentication result from the cache.

        Args:
            payload: The payload used as a lookup key.
            target_host: The proxy's target host the payload was authorised for.

        Returns:
            AuthResult if found, None otherwise. Entries written before a
            field existed (output_header/output_prefix, expires_at,
            identity_token_id/attribution_handle) load with it set to None;
            a legacy signing_key entry is ignored.

        Raises:
            redis.exceptions.TimeoutError: If the Redis read times out.
            CacheError: If there's any other error accessing the cache.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache lookup")
            return None

        try:
            cache_key = self.generate_cache_key(payload, target_host)
            cached_data = await client.get(cache_key)

            if cached_data:
                logger.info(f"Cache hit for key {cache_key[:8]}...")
                auth_response = json.loads(cached_data)

                principal_info = PrincipalInfo.from_dict(
                    auth_response["principal_info"]
                )

                expires_at = auth_response.get("expires_at")
                return AuthResult(
                    api_key=auth_response["api_key"],
                    principal_info=principal_info,
                    output_header=auth_response.get("output_header"),
                    output_prefix=auth_response.get("output_prefix"),
                    expires_at=(
                        datetime.fromisoformat(expires_at) if expires_at else None
                    ),
                    identity_token_id=auth_response.get("identity_token_id"),
                    attribution_handle=auth_response.get("attribution_handle"),
                )

            logger.info(f"Cache miss for key {cache_key[:8]}...")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding cached data: {e}")
            return None
        # Left unwrapped so AuthService can tell a timeout from other failures.
        except RedisTimeoutError:
            raise
        except Exception as e:
            logger.error(f"Error getting from cache: {e}")
            raise CacheError(f"Failed to retrieve from cache: {e}")

    async def cache_auth_response(
        self,
        payload: str,
        target_host: Optional[str],
        api_key: str,
        principal_info: PrincipalInfo,
        ttl_seconds: Optional[int] = None,
        output_header: Optional[str] = None,
        output_prefix: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        identity_token_id: Optional[str] = None,
        attribution_handle: Optional[str] = None,
    ) -> bool:
        """
        Cache an authentication response including API key and principal info.

        Args:
            payload: The payload to use as a cache key.
            target_host: The proxy's target host the payload was authorised for.
            api_key: The API key to cache.
            principal_info: Principal information to cache and log.
            ttl_seconds: Optional TTL override
            output_header: Upstream header that should carry the credential
            output_prefix: Prefix for the credential value
            expires_at: When a minted credential expires
            identity_token_id: ``jti`` of the identity token a minted
                credential was exchanged for
            attribution_handle: Handle a ``pseudonymous`` identity token
                carried

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
            cache_key = self.generate_cache_key(payload, target_host)
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
                "output_header": output_header,
                "output_prefix": output_prefix,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "identity_token_id": identity_token_id,
                "attribution_handle": attribution_handle,
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
        target_host: Optional[str],
        auth_result: AuthResult,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """
        Cache an authentication result.

        Args:
            payload: The payload to use as a cache key.
            target_host: The proxy's target host the payload was authorised for.
            auth_result: The authentication result to cache.
            ttl_seconds: Optional TTL override based on credential expiration.

        Returns:
            True if successfully cached, False otherwise.
        """
        return await self.cache_auth_response(
            payload,
            target_host,
            auth_result.api_key,
            auth_result.principal_info,
            ttl_seconds,
            output_header=auth_result.output_header,
            output_prefix=auth_result.output_prefix,
            expires_at=auth_result.expires_at,
            identity_token_id=auth_result.identity_token_id,
            attribution_handle=auth_result.attribution_handle,
        )

    @capture_async()
    async def cache_api_key(
        self,
        payload: str,
        target_host: Optional[str],
        api_key: str,
        principal_info: PrincipalInfo,
    ) -> bool:
        """
        Cache an API key and principal info.

        Args:
            payload: The payload to use as a cache key.
            target_host: The proxy's target host the payload was authorised for.
            api_key: The API key to cache.
            principal_info: Principal information to cache and log.

        Returns:
            True if successfully cached, False otherwise.
        """
        return await self.cache_auth_response(
            payload, target_host, api_key, principal_info
        )

    @capture_async()
    async def invalidate_cache_entry(
        self, payload: str, target_host: Optional[str]
    ) -> bool:
        """
        Invalidate a cache entry.

        Args:
            payload: The payload whose cache entry should be invalidated.
            target_host: The proxy's target host the payload was authorised for.

        Returns:
            True if successfully invalidated or entry didn't exist, False on error.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache invalidation")
            return False

        try:
            cache_key = self.generate_cache_key(payload, target_host)
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
