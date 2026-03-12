"""Authentication service module.

Orchestrates authentication with caching. The actual identity resolution,
secret retrieval, and signing are delegated to a pluggable AuthBackend.
"""

import asyncio
import logging
from typing import Any, Optional

from aws_xray_sdk.core import xray_recorder

from portunus.backends.protocols import AuthBackend
from portunus.config import config
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    PayloadError,
)
from portunus.models import AuthResult
from portunus.services.cache_service import CacheService

logger = logging.getLogger("api.access")


class AuthService:
    """Orchestrates authentication with caching around a pluggable backend.

    The cache layer is backend-agnostic: it uses SHA-256 of the raw
    payload as the cache key regardless of what the backend does with it.
    """

    def __init__(
        self,
        auth_backend: AuthBackend,
        cache_service: Optional[CacheService] = None,
    ):
        self.auth_backend = auth_backend
        self.cache_service = cache_service or CacheService()

    @xray_recorder.capture_async()  # type: ignore
    async def authenticate(
        self,
        raw_payload: str,
        request_id: str,
        target_host: Optional[str] = None,
    ) -> AuthResult:
        """Authenticate a request: cache check, then delegate to backend.

        Args:
            raw_payload: Opaque auth payload string from the proxy.
            request_id: Unique request ID for logging/tracing.
            target_host: Optional target host for validation.

        Returns:
            AuthResult with api_key, optional signing_key, and
            principal_info.

        Raises:
            PayloadError: If the payload cannot be decoded.
            CredentialsError: If credentials are invalid or expired.
            AuthenticationError: If authentication fails.
        """
        # Check cache first
        if raw_payload:
            try:
                async with asyncio.timeout(5):
                    cached = await self.cache_service.get_cached_auth_result(
                        raw_payload
                    )
                    if cached:
                        return AuthResult(
                            api_key=cached.api_key,
                            signing_key=cached.signing_key,
                            principal_info=cached.principal_info,
                        )
            except Exception as e:
                logger.error(f"Cache read error during auth: {e}")

        # Delegate to backend
        try:
            auth_result = await self.auth_backend.authenticate(
                raw_payload, request_id, target_host
            )

            # Cache the result (best effort)
            if raw_payload and auth_result.successful:
                try:
                    async with asyncio.timeout(3):
                        ttl = config.redis.cache_duration
                        await self.cache_service.cache_auth_result(
                            raw_payload, auth_result, ttl
                        )
                except Exception as e:
                    logger.error(f"Cache write error during auth: {e}")

            return auth_result
        except (PayloadError, CredentialsError):
            raise
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")

    async def sign_request(
        self,
        raw_payload: str,
        signable_request: Any,
        auth_result: AuthResult,
    ) -> dict[str, str] | None:
        """Delegate request signing to the backend."""
        return await self.auth_backend.sign_request(
            raw_payload, signable_request, auth_result
        )
