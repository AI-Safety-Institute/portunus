"""WebSocket authentication for the relay endpoint.

Authenticates WebSocket upgrade requests using the same AuthService
as HTTP requests. Reads the Authorization header before accepting
the connection.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from starlette.websockets import WebSocket

from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
)
from portunus.models import AuthPayload, AuthResult
from portunus.relay import WsCloseCode
from portunus.services.auth_service import AuthService

logger = logging.getLogger("api.access")


@dataclass
class WsAuthResult:
    """Result of WebSocket authentication.

    Attributes:
        auth_result: The underlying AuthResult from AuthService.
        api_key: The API key to use for upstream connection.
        secret_arn: The secret ARN from the auth payload, for Kinesis metadata.
    """

    auth_result: AuthResult
    api_key: str
    secret_arn: Optional[str] = None


async def _close_ws(websocket: WebSocket, code: int, reason: str) -> None:
    """Close a WebSocket, suppressing errors if the connection is already gone.

    This is needed because close() before accept() can behave differently
    across ASGI servers.
    """
    try:
        await websocket.close(code=code, reason=reason)
    except Exception:
        pass


async def authenticate_ws(
    websocket: WebSocket,
    auth_service: AuthService,
    request_id: str,
    target_host: Optional[str] = None,
) -> Optional[WsAuthResult]:
    """Authenticate a WebSocket upgrade request.

    Reads the Authorization header from the WebSocket handshake,
    strips the Bearer prefix, and authenticates via AuthService.

    On failure, closes the WebSocket with an appropriate code:
    - 4001: Missing or invalid authorization
    - 4003: Forbidden (AWS permissions error)

    Args:
        websocket: The WebSocket connection (not yet accepted).
        auth_service: The AuthService instance for authentication.
        request_id: Unique request ID for logging/correlation.
        target_host: Optional target host for validation.

    Returns:
        WsAuthResult on success, None on failure (connection already closed).
    """
    auth_header = websocket.headers.get("authorization", "")

    if not auth_header:
        logger.warning(f"WS {request_id}: No authorization header")
        await _close_ws(
            websocket,
            code=WsCloseCode.AUTH_FAILED,
            reason="Missing authorization header",
        )
        return None

    # Strip Bearer prefix
    raw_payload = auth_header
    if raw_payload.lower().startswith("bearer "):
        raw_payload = raw_payload[7:]

    try:
        payload = AuthPayload.from_contents(raw_payload, target_host=target_host)
        auth_result = await auth_service.authenticate(payload, request_id, target_host)
    except (PayloadError, CredentialsError) as e:
        logger.warning(f"WS {request_id}: Auth failed: {e.message}")
        await _close_ws(
            websocket,
            code=WsCloseCode.AUTH_FAILED,
            reason="Invalid authorization",
        )
        return None
    except (AuthenticationError, FetchSecretError) as e:
        logger.warning(f"WS {request_id}: Auth forbidden: {e.message}")
        await _close_ws(websocket, code=WsCloseCode.FORBIDDEN, reason="Forbidden")
        return None
    except Exception as e:
        logger.error(f"WS {request_id}: Unexpected auth error: {e}")
        await _close_ws(
            websocket,
            code=WsCloseCode.AUTH_FAILED,
            reason="Authentication error",
        )
        return None

    return WsAuthResult(
        auth_result=auth_result,
        api_key=auth_result.api_key,
        secret_arn=payload.secret_arn,
    )
