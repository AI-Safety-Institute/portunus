"""
Service-to-service authentication for Portunus endpoints.

The Envoy proxy attaches a shared secret header (``PORTUNUS_API_KEY`` in the
``PORTUNUS_API_KEY_HEADER`` header, default ``x-api-key``) to every call it
makes to Portunus. Portunus requires the same secret and rejects callers of
the service endpoints (/authorise, /log/*, /cache/flush and WebSocket
upgrades) that don't present it.

``ServiceAuth`` is the parsed, always-valid form of the raw (optional)
``ServiceAuthConfig``: it is constructed once when the app module is
imported, so a missing PORTUNUS_API_KEY fails fast at startup and every
consumer past that boundary works with a plain ``str`` secret.
"""

import logging
import secrets
from dataclasses import dataclass
from typing import Mapping

from fastapi import HTTPException, Request

from portunus.config import PortunusConfig

logger = logging.getLogger("api.access")


@dataclass(frozen=True)
class ServiceAuth:
    """Validated service-auth settings. Construct via ``from_config``.

    Attributes:
        secret: Shared secret the proxy must present.
        header: Header name carrying the shared secret.
    """

    secret: str
    header: str

    @classmethod
    def from_config(cls, config: PortunusConfig) -> "ServiceAuth":
        """Parse the raw config, failing fast if the secret is missing.

        Raises:
            RuntimeError: If PORTUNUS_API_KEY is unset or empty.
        """
        if not config.service_auth.shared_secret:
            raise RuntimeError(
                "PORTUNUS_API_KEY must be set: the service endpoints "
                "(/authorise, /log/*, /cache/flush, WebSocket relay) require "
                "the proxy's shared secret. Set the same value on the proxy "
                "and Portunus containers."
            )
        return cls(
            secret=config.service_auth.shared_secret,
            header=config.service_auth.header,
        )

    def valid(self, headers: Mapping[str, str]) -> bool:
        """Check whether request headers carry the shared secret.

        Args:
            headers: Case-insensitive request headers (Starlette Headers).

        Returns:
            True if the configured header matches the secret
            (constant-time comparison).
        """
        provided = headers.get(self.header) or ""
        return secrets.compare_digest(provided.encode(), self.secret.encode())

    async def require(self, request: Request) -> None:
        """FastAPI dependency enforcing the shared secret on HTTP endpoints.

        Raises:
            HTTPException: 401 if the request does not present the secret.
        """
        if not self.valid(request.headers):
            logger.warning(
                f"Rejected request to {request.url.path}: "
                "missing or invalid service credentials"
            )
            raise HTTPException(
                status_code=401, detail="Missing or invalid service credentials"
            )
