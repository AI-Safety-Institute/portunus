"""
API authentication response caching service module.

This module contains the CacheService class, which is responsible for caching
and retrieving authentication responses in Redis.
"""

import hashlib
import json
import logging
from typing import Optional, Tuple

from aiocache import cached  # type: ignore[import-untyped]
from aws_xray_sdk.core import xray_recorder

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

    async def get_cached_auth_response(
        self, payload: str
    ) -> Optional[Tuple[str, PrincipalInfo, Optional[SigningKey]]]:
        """
        Get an authentication response from the cache.

        Retrieves the API key and principal information for a cached authentication
        response, using the payload as a lookup key.

        Args:
            payload: The payload used as a lookup key.

        Returns:
            A tuple of (api_key, principal_info) if found, None otherwise.

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
                # Deserialize the JSON data
                auth_response = json.loads(cached_data)

                # Convert the principal_info dict back to a PrincipalInfo object
                principal_info_dict = auth_response["principal_info"]
                principal_info = PrincipalInfo.from_dict(principal_info_dict)

                signing_key = (
                    SigningKey(
                        provider_id=auth_response["signing_key"]["provider_id"],
                        kms_key_arn=auth_response["signing_key"]["kms_key_arn"],
                    )
                    if "signing_key" in auth_response
                    and auth_response["signing_key"] is not None
                    else None
                )

                return auth_response["api_key"], principal_info, signing_key

            logger.info(f"Cache miss for key {cache_key[:8]}...")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding cached data: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting from cache: {e}")
            raise CacheError(f"Failed to retrieve from cache: {e}")

    @cached(ttl=500)
    async def get_cached_auth_result(self, payload: str) -> Optional[AuthResult]:
        """
        Get an authentication result from the cache.

        Args:
            payload: The payload used as a lookup key.

        Returns:
            AuthResult object if found, None otherwise.
        """
        response = await self.get_cached_auth_response(payload)
        if response:
            api_key, principal_info, signing_key = response
            return AuthResult(
                api_key=api_key, signing_key=signing_key, principal_info=principal_info
            )
        return None

    async def cache_auth_response(
        self,
        payload: str,
        api_key: str,
        signing_key: Optional[SigningKey],
        principal_info: PrincipalInfo,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """
        Cache an authentication response including API key and principal info.

        Args:
            payload: The payload to use as a cache key.
            api_key: The API key to cache.
            signing_key: The request signing key details for this api key.
            principal_info: Principal information to cache and log.
            ttl_seconds: Optional TTL override

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

    @xray_recorder.capture_async()  # type: ignore
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
        )

    @xray_recorder.capture_async()  # type: ignore
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

    @xray_recorder.capture_async()  # type: ignore
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

    @xray_recorder.capture_async()  # type: ignore
    async def health_check(self) -> bool:
        """
        Check if Redis cache is available.

        Returns:
            True if Redis is available, False otherwise.
        """
        return await self.state_service.health_check()
