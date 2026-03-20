"""Tests for WebSocket authentication."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from portunus.exceptions import CredentialsError, FetchSecretError, PayloadError
from portunus.models import AuthResult, PrincipalInfo
from portunus.relay.auth import authenticate_ws


@pytest.fixture
def mock_websocket():
    """Create a mock WebSocket with headers."""
    ws = AsyncMock()
    ws.headers = {}
    ws.close = AsyncMock()
    return ws


@pytest.fixture
def mock_auth_service():
    """Create a mock AuthService."""
    service = AsyncMock()
    return service


class TestAuthenticateWs:
    """Tests for authenticate_ws function."""

    @pytest.mark.asyncio
    async def test_no_auth_header_closes_4001(self, mock_websocket, mock_auth_service):
        """Missing authorization header closes with 4001."""
        mock_websocket.headers = {}

        result = await authenticate_ws(
            mock_websocket, mock_auth_service, "test-req-id"
        )

        assert result is None
        mock_websocket.close.assert_called_once_with(
            code=4001, reason="Missing authorization header"
        )

    @pytest.mark.asyncio
    async def test_empty_auth_header_closes_4001(
        self, mock_websocket, mock_auth_service
    ):
        """Empty authorization header closes with 4001."""
        mock_websocket.headers = {"authorization": ""}

        result = await authenticate_ws(
            mock_websocket, mock_auth_service, "test-req-id"
        )

        assert result is None
        mock_websocket.close.assert_called_once_with(
            code=4001, reason="Missing authorization header"
        )

    @pytest.mark.asyncio
    async def test_invalid_payload_closes_4001(
        self, mock_websocket, mock_auth_service
    ):
        """Invalid payload closes with 4001."""
        mock_websocket.headers = {"authorization": "Bearer invalid_payload"}

        with patch(
            "portunus.relay.auth.AuthPayload.from_contents",
            side_effect=PayloadError("bad payload"),
        ):
            result = await authenticate_ws(
                mock_websocket, mock_auth_service, "test-req-id"
            )

        assert result is None
        mock_websocket.close.assert_called_once_with(
            code=4001, reason="Invalid authorization"
        )

    @pytest.mark.asyncio
    async def test_credentials_error_closes_4001(
        self, mock_websocket, mock_auth_service
    ):
        """Credentials error closes with 4001."""
        mock_websocket.headers = {"authorization": "Bearer some_payload"}

        with patch(
            "portunus.relay.auth.AuthPayload.from_contents"
        ) as mock_from_contents:
            mock_from_contents.return_value = MagicMock()
            mock_auth_service.authenticate.side_effect = CredentialsError(
                "bad creds"
            )

            result = await authenticate_ws(
                mock_websocket, mock_auth_service, "test-req-id"
            )

        assert result is None
        mock_websocket.close.assert_called_once_with(
            code=4001, reason="Invalid authorization"
        )

    @pytest.mark.asyncio
    async def test_fetch_secret_error_closes_4003(
        self, mock_websocket, mock_auth_service
    ):
        """FetchSecretError closes with 4003."""
        mock_websocket.headers = {"authorization": "Bearer some_payload"}

        with patch(
            "portunus.relay.auth.AuthPayload.from_contents"
        ) as mock_from_contents:
            mock_from_contents.return_value = MagicMock()
            mock_auth_service.authenticate.side_effect = FetchSecretError(
                http_status_code=403, message="forbidden"
            )

            result = await authenticate_ws(
                mock_websocket, mock_auth_service, "test-req-id"
            )

        assert result is None
        mock_websocket.close.assert_called_once_with(
            code=4003, reason="Forbidden"
        )

    @pytest.mark.asyncio
    async def test_successful_auth_returns_result(
        self, mock_websocket, mock_auth_service
    ):
        """Successful auth returns WsAuthResult."""
        mock_websocket.headers = {"authorization": "Bearer some_valid_payload"}

        auth_result = AuthResult(
            api_key="sk-test-123",
            signing_key=None,
            principal_info=PrincipalInfo(
                arn="arn:aws:sts::123456:assumed-role/TestRole/session",
                account_id="123456",
            ),
        )

        with patch(
            "portunus.relay.auth.AuthPayload.from_contents"
        ) as mock_from_contents:
            mock_from_contents.return_value = MagicMock()
            mock_auth_service.authenticate.return_value = auth_result

            result = await authenticate_ws(
                mock_websocket, mock_auth_service, "test-req-id"
            )

        assert result is not None
        assert result.api_key == "sk-test-123"
        assert result.auth_result is auth_result
        mock_websocket.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_strips_bearer_prefix(self, mock_websocket, mock_auth_service):
        """Bearer prefix is stripped before passing to AuthPayload."""
        mock_websocket.headers = {"authorization": "Bearer my_payload_data"}

        auth_result = AuthResult(
            api_key="sk-test",
            signing_key=None,
            principal_info=PrincipalInfo(),
        )

        with patch(
            "portunus.relay.auth.AuthPayload.from_contents"
        ) as mock_from_contents:
            mock_from_contents.return_value = MagicMock()
            mock_auth_service.authenticate.return_value = auth_result

            await authenticate_ws(
                mock_websocket, mock_auth_service, "test-req-id"
            )

            # Verify Bearer was stripped
            mock_from_contents.assert_called_once_with(
                "my_payload_data", target_host=None
            )
