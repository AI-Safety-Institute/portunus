"""
Service-to-service authentication for Portunus endpoints.

The Envoy proxy attaches a shared secret header (``PORTUNUS_API_KEY`` in the
``PORTUNUS_API_KEY_HEADER`` header, default ``x-api-key``) to every call it
makes to Portunus. Portunus requires the same secret to be configured and
rejects callers of the service endpoints (/authorise, /log/*, /cache/flush
and WebSocket upgrades) that don't present it.

The secret is mandatory: startup fails if it is unset, and requests are
denied if validation is somehow reached without one configured.
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
        True if the configured header matches the configured secret
        (constant-time comparison). False if no secret is configured —
        the service refuses to start in that state, so this is a
        defence-in-depth fallback.
    """
    expected = config.service_auth.shared_secret
    if not expected:
        return False
    provided = headers.get(config.service_auth.header) or ""
    return secrets.compare_digest(provided.encode(), expected.encode())


async def require_shared_secret(request: Request) -> None:
    """FastAPI dependency enforcing the shared secret on HTTP endpoints.

    Raises:
        HTTPException: 401 if the request does not present the shared secret.
    """
    if not shared_secret_valid(request.headers):
        logger.warning(
            f"Rejected request to {request.url.path}: "
            "missing or invalid service credentials"
        )
        raise HTTPException(
            status_code=401, detail="Missing or invalid service credentials"
        )


def ensure_shared_secret_configured() -> None:
    """Fail startup unless the proxy shared secret is configured.

    Raises:
        RuntimeError: If PORTUNUS_API_KEY is unset or empty.
    """
    if not config.service_auth.shared_secret:
        raise RuntimeError(
            "PORTUNUS_API_KEY must be set: the service endpoints (/authorise, "
            "/log/*, /cache/flush, WebSocket relay) require the proxy's shared "
            "secret. Set the same value on the proxy and Portunus containers."
        )
