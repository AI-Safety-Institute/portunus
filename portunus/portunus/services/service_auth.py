"""
Service-to-service authentication for Portunus endpoints.

The Envoy proxy attaches a shared secret header (``PORTUNUS_API_KEY`` in the
``PORTUNUS_API_KEY_HEADER`` header, default ``x-api-key``) to every call it
makes to Portunus. When Portunus is configured with the same secret, the
service endpoints (/authorise, /log/*, /cache/flush and WebSocket upgrades)
reject callers that don't present it.

When no secret is configured, the check is disabled and access control falls
back to the network layer. A warning is logged at startup in that case.
"""

import logging
import secrets
from typing import Mapping

from fastapi import HTTPException, Request

from portunus.config import config

logger = logging.getLogger("api.access")


def shared_secret_valid(headers: Mapping[str, str]) -> bool:
    """Check whether request headers carry the configured shared secret.

    Args:
        headers: Case-insensitive request headers (Starlette Headers).

    Returns:
        True if no shared secret is configured, or if the configured header
        matches the configured secret (constant-time comparison).
    """
    expected = config.service_auth.shared_secret
    if not expected:
        return True
    provided = headers.get(config.service_auth.header) or ""
    return secrets.compare_digest(provided.encode(), expected.encode())


async def require_shared_secret(request: Request) -> None:
    """FastAPI dependency enforcing the shared secret on HTTP endpoints.

    Raises:
        HTTPException: 401 if a shared secret is configured and the request
            does not present it.
    """
    if not shared_secret_valid(request.headers):
        logger.warning(
            f"Rejected request to {request.url.path}: "
            "missing or invalid service credentials"
        )
        raise HTTPException(
            status_code=401, detail="Missing or invalid service credentials"
        )


def warn_if_unauthenticated() -> None:
    """Log a startup warning when service endpoints are unauthenticated."""
    if not config.service_auth.shared_secret:
        logger.warning(
            "PORTUNUS_API_KEY is not set: service endpoints (/authorise, "
            "/log/*, /cache/flush, WebSocket relay) accept unauthenticated "
            "requests. Access must be restricted at the network layer."
        )
