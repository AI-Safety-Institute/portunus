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
from portunus.models import AuthResult
from portunus.services.state_service import StateService

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


def auth_cache_key(payload: str, target_host: Optional[str]) -> str:
    """Hash payload + target_host into a Redis-safe cache key.

    The one definition of the key, for Redis and any in-process tier in
    front of it. ``target_host`` is part of the key so a cached result is
    only reused for the upstream it was authorised for — the host
    restriction ``SecretValidationService.validate_secret`` enforces on a
    miss.

    The value is deliberately the formula Portunus has always used: changing
    it would invalidate every Redis entry on deploy and cost a burst of full
    authentications. The newline join is unambiguous because HTTP header
    values cannot contain a newline and the host is operator configuration.
    """
    return hashlib.sha256(f"{payload}\n{target_host or ''}".encode("utf-8")).hexdigest()


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

        Creates a SHA-256 hash over the payload and the target host (see
        :func:`auth_cache_key`) to use as a Redis key, so keys are of
        consistent length, don't contain sensitive information, and a result
        authorised for one proxy's upstream is never a hit for a proxy with a
        different one.

        Args:
            payload: The payload to use for the cache key.
            target_host: The proxy's target host, or None when it sent none.

        Returns:
            A hash of the payload and target host to use as a cache key.
        """
        return auth_cache_key(payload, target_host)

    async def get_cached_auth_result(
        self, payload: str, target_host: Optional[str]
    ) -> Optional[AuthResult]:
        """
        Get an authentication result from the cache.

        Args:
            payload: The payload used as a lookup key.
            target_host: The proxy's target host the payload was authorised for.

        Returns:
            AuthResult if found, None otherwise. Entries written before
            output_header/output_prefix existed load with both set to None;
            a legacy signing_key entry is ignored.

        Raises:
            redis.exceptions.TimeoutError: If the Redis read times out.
            TimeoutError: If waiting for a pooled connection times out.
            CacheError: If there's any other error accessing the cache.
        """
        try:
            cache_key = self.generate_cache_key(payload, target_host)
            cached_data = await self.state_service.execute_redis(
                lambda client: client.get(cache_key)
            )

            if not cached_data:
                logger.debug("Cache miss for key %s...", cache_key[:8])
                return None

            logger.debug("Cache hit for key %s...", cache_key[:8])
            return AuthResult.from_dict(json.loads(cached_data))
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding cached data: {e}")
            return None
        # Left unwrapped so AuthService can tell a timeout from other failures.
        except (RedisTimeoutError, TimeoutError):
            raise
        except Exception as e:
            logger.error(f"Error getting from cache: {e}")
            raise CacheError(f"Failed to retrieve from cache: {e}")

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

        Raises:
            CacheError: If there's an error storing in the cache.
        """
        try:
            cache_key = self.generate_cache_key(payload, target_host)
            effective_ttl = (
                ttl_seconds if ttl_seconds is not None else self.cache_duration
            )

            # Skip caching if TTL is 0 or negative (credentials already expired)
            if effective_ttl <= 0:
                logger.info(
                    f"Skipping cache for principal {auth_result.principal_info.arn}: "
                    f"TTL is {effective_ttl}s"
                )
                return False

            # Store both API key and principal info as JSON
            auth_response = {
                "api_key": auth_result.api_key,
                "principal_info": auth_result.principal_info.to_dict(),
                "output_header": auth_result.output_header,
                "output_prefix": auth_result.output_prefix,
                "expires_at": (
                    auth_result.expires_at.isoformat()
                    if auth_result.expires_at
                    else None
                ),
            }

            encoded_response = json.dumps(auth_response)
            result = await self.state_service.execute_redis(
                lambda client: client.psetex(
                    cache_key, effective_ttl * 1000, encoded_response
                )
            )
            if not result:
                return False

            logger.info(
                f"Cached auth response for principal: "
                f"{auth_result.principal_info.arn}, "
                f"TTL capped at {effective_ttl}s"
            )

            return bool(result)
        except Exception as e:
            logger.error(f"Error caching auth response: {e}")
            raise CacheError(f"Failed to store in cache: {e}")

    async def flush_all(self) -> bool:
        """
        Flush the entire auth cache.

        Returns:
            True if successfully flushed, False on error.

        Raises:
            CacheError: If there's an error flushing the cache.
        """
        try:
            result = await self.state_service.execute_redis(
                lambda client: client.flushdb()
            )
            if not result:
                return False
            logger.info("Flushed all auth cache entries")
            return True
        except Exception as e:
            logger.error(f"Error flushing cache: {e}")
            raise CacheError(f"Failed to flush cache: {e}")

    async def health_check(self) -> bool:
        """
        Check if Redis cache is available.

        Returns:
            True if Redis is available, False otherwise.
        """
        return await self.state_service.health_check()
