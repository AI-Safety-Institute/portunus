"""Auth-response caching: shared Redis plus a per-task in-process layer.

A flush must be honest fleet-wide even though it runs on one task: the
in-process layers on every other task are unreachable directly, so
``flush_all`` rewrites a flush token in Redis and each task re-checks it at
most ``flush_poll_seconds`` apart, dropping its in-process layer on change.
"""

import hashlib
import json
import logging
import time
import uuid
from typing import Optional

from portunus.config import config
from portunus.exceptions import CacheError
from portunus.models import AuthResult, PrincipalInfo, SigningKey
from portunus.services.state_service import StateService
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

# Bounds how long an in-process entry can outlive its Redis counterpart for
# non-flush changes (entry TTL expiry, secret rotation without a flush).
# Flush convergence is governed by the flush token, not this TTL.
L1_TTL_SECONDS = 60.0

# Rewritten (not INCRed) on every flush: FLUSHDB deletes this key too, and a
# counter reborn at 1 would collide with a remembered 1 and hide the flush.
FLUSH_TOKEN_KEY = "cache:flush-token"


def normalise_target_host(host: Optional[str]) -> Optional[str]:
    """Canonicalise a target host for keying and host-restriction checks.

    DNS is case-insensitive and ``:443`` is the implicit HTTPS default (all
    proxied providers are HTTPS), so ``API.Host:443`` and ``api.host`` are one
    endpoint; only ``:443`` is stripped, any other port is kept distinct.

    Used by BOTH :meth:`CacheService.generate_cache_key` and
    ``validate_and_extract_api_key`` — they must stay in lockstep, else a cache
    hit could admit a host the miss-path validator would reject. ``None``/``""``
    pass through unchanged.
    """
    if not host:
        return host
    normalised = host.strip().lower()
    if normalised.endswith(":443"):
        normalised = normalised[: -len(":443")]
    return normalised


class CacheService:
    """Caches authentication responses in shared Redis plus a local layer.

    Attributes:
        state_service: The service providing access to Redis.
        cache_duration: How long to cache entries in Redis (seconds).
        flush_poll_seconds: How often to re-check the shared flush token.
    """

    def __init__(
        self,
        state_service: Optional[StateService] = None,
        flush_poll_seconds: Optional[float] = None,
    ):
        """Initialize the CacheService."""
        self.state_service = state_service or StateService()
        self.cache_duration = config.redis.cache_duration
        self.flush_poll_seconds = (
            flush_poll_seconds
            if flush_poll_seconds is not None
            else config.redis.flush_poll_seconds
        )
        self._l1: dict[str, tuple[float, AuthResult]] = {}
        self._flush_token: Optional[str] = None
        self._flush_token_checked_at = float("-inf")

    async def _drop_l1_if_flushed_elsewhere(self, client) -> None:
        """Re-check the shared flush token; drop the in-process layer on change."""
        now = time.monotonic()
        if now - self._flush_token_checked_at < self.flush_poll_seconds:
            return
        try:
            token = await client.get(FLUSH_TOKEN_KEY)
        except Exception as e:
            # Keep serving the in-process layer: no flush can land while
            # Redis is unreachable, so there is nothing new to converge to.
            logger.warning("Flush-token check failed: %s", type(e).__name__)
            return
        self._flush_token_checked_at = now
        if token != self._flush_token:
            self._l1.clear()
            self._flush_token = token

    def generate_cache_key(
        self, payload: str, target_host: Optional[str] = None
    ) -> str:
        """Hash payload + target_host into a Redis-safe cache key.

        ``target_host`` MUST be included: without it, a bearer authorised for
        provider A could reuse a cached api_key through a proxy fronting
        provider B, bypassing the host restriction
        ``validate_and_extract_api_key`` enforces on miss.

        The two components are hashed independently (not joined with a
        delimiter) so no (host, payload) pair can collide by shifting bytes
        across a separator — e.g. ``("a:b","c")`` vs ``("a","b:c")``. Host is
        normalised as in the miss-path check, keeping key and recheck
        consistent.
        """
        host_component = normalise_target_host(target_host) or ""
        composite = (
            hashlib.sha256(host_component.encode("utf-8")).digest()
            + hashlib.sha256(payload.encode("utf-8")).digest()
        )
        return hashlib.sha256(composite).hexdigest()

    async def get_cached_auth_result(
        self, payload: str, target_host: Optional[str] = None
    ) -> Optional[AuthResult]:
        """Look up a cached AuthResult by (payload, target_host)."""
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache lookup")
            return None

        await self._drop_l1_if_flushed_elsewhere(client)

        cache_key = self.generate_cache_key(payload, target_host)
        l1_entry = self._l1.get(cache_key)
        if l1_entry is not None:
            expires_at, l1_result = l1_entry
            if time.monotonic() < expires_at:
                return l1_result
            del self._l1[cache_key]

        try:
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
            result = AuthResult(
                api_key=auth_response["api_key"],
                signing_key=signing_key,
                principal_info=principal_info,
            )
            self._l1[cache_key] = (time.monotonic() + L1_TTL_SECONDS, result)
            return result
        except json.JSONDecodeError as e:
            # The repr includes the offending document — here a cached auth
            # response with the upstream API key. Log only the class name.
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

            # Skip caching when TTL <= 0 (credentials already expired).
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

    @capture_async()
    async def flush_all(self) -> bool:
        """Flush the entire auth cache.

        Returns:
            True if flushed, False on error.

        Raises:
            CacheError: If flushing fails.
        """
        client = await self.state_service.acquire_redis_connection()
        if not client:
            logger.warning("Redis client unavailable for cache flush")
            return False

        try:
            # Token is written AFTER the flush: set first, and a peer could
            # observe it, drop its layer, and re-fill from not-yet-flushed
            # Redis — stale data with no later signal to evict it.
            await client.flushdb()
            new_token = uuid.uuid4().hex
            await client.set(FLUSH_TOKEN_KEY, new_token)
            self._l1.clear()
            self._flush_token = new_token
            logger.info("Flushed all auth cache entries")
            return True
        except Exception as e:
            logger.error("Error flushing cache: %s", type(e).__name__)
            raise CacheError(f"Failed to flush cache: {type(e).__name__}")

    @capture_async()
    async def health_check(self) -> bool:
        """Check if the Redis cache is available."""
        return await self.state_service.health_check()
