"""
API authentication response caching service module.

This module contains the CacheService class, which is responsible for caching
and retrieving authentication responses in Redis.
"""

import hashlib
import json
import logging
from typing import Optional

from portunus.config import config
from portunus.exceptions import CacheError
from portunus.models import AuthResult, PrincipalInfo, SigningKey
from portunus.services.state_service import StateService

logger = logging.getLogger("api.access")


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

    def generate_cache_key(
        self, payload: str, target_host: Optional[str] = None
    ) -> str:
        """Hash payload + target_host into a Redis-safe cache key.

        ``target_host`` MUST be included: the secret carries an optional
        ``host`` restriction that ``SecretValidationService`` enforces on
        cache-miss. Without ``target_host`` in the key, a bearer authorised
        for provider A could re-use a cached api_key when sent through a
        proxy fronting provider B — silently bypassing host enforcement.
        """
        composite = f"{target_host or ''}:{payload}"
        return hashlib.sha256(composite.encode("utf-8")).hexdigest()

    async def get_cached_auth_result(
        self, payload: str, target_host: Optional[str] = None
    ) -> Optional[AuthResult]:
        """Look up a cached AuthResult by (payload, target_host)."""
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache lookup")
            return None

        try:
            cache_key = self.generate_cache_key(payload, target_host)
            cached_data = await client.get(cache_key)

            if not cached_data:
                logger.debug("Cache miss for key %s...", cache_key[:8])
                return None

            logger.debug("Cache hit for key %s...", cache_key[:8])
            auth_response = json.loads(cached_data)
            principal_info = PrincipalInfo.from_dict(auth_response["principal_info"])
            signing_key_dict = auth_response.get("signing_key")
            signing_key = (
                SigningKey(
                    provider_id=signing_key_dict["provider_id"],
                    kms_key_arn=signing_key_dict["kms_key_arn"],
                )
                if signing_key_dict
                else None
            )
            return AuthResult(
                api_key=auth_response["api_key"],
                signing_key=signing_key,
                principal_info=principal_info,
            )
        except json.JSONDecodeError as e:
            # JSONDecodeError repr includes the offending document snippet,
            # which here is a cached auth response containing the upstream
            # API key. Log only the exception class name.
            logger.error("Error decoding cached data: %s", type(e).__name__)
            return None
        except Exception as e:
            logger.error("Error getting from cache: %s", type(e).__name__)
            raise CacheError(f"Failed to retrieve from cache: {type(e).__name__}")

    async def cache_auth_result(
        self,
        payload: str,
        auth_result: AuthResult,
        ttl_seconds: Optional[int] = None,
        target_host: Optional[str] = None,
    ) -> bool:
        """Cache an AuthResult keyed by (payload, target_host)."""
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
                    f"Skipping cache for principal {auth_result.principal_info.arn}: "
                    f"TTL is {effective_ttl}s"
                )
                return False

            auth_response = {
                "api_key": auth_result.api_key,
                "principal_info": auth_result.principal_info.to_dict(),
                "signing_key": (
                    auth_result.signing_key.to_dict()
                    if auth_result.signing_key
                    else None
                ),
            }

            result = await client.setex(
                cache_key, effective_ttl, json.dumps(auth_response)
            )

            logger.info(
                f"Cached auth response for principal: "
                f"{auth_result.principal_info.arn}, "
                f"expires in {effective_ttl}s)"
            )

            return bool(result)
        except Exception as e:
            logger.error("Error caching auth response: %s", type(e).__name__)
            raise CacheError(f"Failed to store in cache: {type(e).__name__}")

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
            logger.error("Error flushing cache: %s", type(e).__name__)
            raise CacheError(f"Failed to flush cache: {type(e).__name__}")

    async def health_check(self) -> bool:
        """
        Check if Redis cache is available.

        Returns:
            True if Redis is available, False otherwise.
        """
        return await self.state_service.health_check()
