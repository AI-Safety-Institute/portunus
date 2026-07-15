"""Tests for WebSocket relay handler."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from portunus.models import AuthResult, PrincipalInfo
from portunus.relay.auth import WsAuthResult
from portunus.relay.handler import handle_ws_connection


@pytest.fixture
def mock_websocket():
    """Create a mock WebSocket."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.close = AsyncMock()
    ws.send_text = AsyncMock()
    ws.receive_text = AsyncMock()
    ws.headers = {
        "authorization": "Bearer test_payload",
        "x-portunus-target-host": "localhost",
        "x-portunus-target-port": "8080",
        "x-portunus-target-use-tls": "false",
    }
    ws.scope = {"query_string": b""}
    return ws


@pytest.fixture
def mock_auth_service():
    """Create a mock AuthService."""
    return AsyncMock()


@pytest.fixture
def mock_publish_service():
    """Create a mock PublishService."""
    service = AsyncMock()
    service.publish_metadata = AsyncMock(return_value=True)
    service.publish_to_kinesis_data_stream = AsyncMock(return_value=True)
    return service


@pytest.fixture
def auth_result():
    """Create a test AuthResult."""
    return AuthResult(
        api_key="sk-test-key",
        signing_key=None,
        principal_info=PrincipalInfo(
            arn="arn:aws:sts::123:assumed-role/TestRole/session",
            account_id="123",
        ),
    )


@pytest.fixture
def ws_auth_result(auth_result):
    """Create a test WsAuthResult."""
    return WsAuthResult(auth_result=auth_result, api_key="sk-test-key")


class TestHandleWsConnection:
    """Tests for handle_ws_connection function."""

    @pytest.mark.asyncio
    async def test_auth_failure_returns_early(
        self, mock_websocket, mock_auth_service, mock_publish_service
    ):
        """If auth fails, connection is not accepted."""
        with patch("portunus.relay.handler.authenticate_ws", return_value=None):
            await handle_ws_connection(
                mock_websocket,
                "v1/responses",
                mock_auth_service,
                mock_publish_service,
                "test-req",
            )

        mock_websocket.accept.assert_not_called()

    @pytest.mark.asyncio
    async def test_upstream_connect_failure_closes_client(
        self,
        mock_websocket,
        mock_auth_service,
        mock_publish_service,
        ws_auth_result,
    ):
        """Failed upstream connection closes client with 1011."""
        with (
            patch(
                "portunus.relay.handler.authenticate_ws",
                return_value=ws_auth_result,
            ),
            patch("portunus.relay.handler.config") as mock_config,
            patch(
                "portunus.relay.handler.ws_connect",
                side_effect=Exception("Connection refused"),
            ),
        ):
            mock_config.relay.max_message_size = 10485760
            mock_config.relay.max_connection_lifetime = 60

            await handle_ws_connection(
                mock_websocket,
                "v1/responses",
                mock_auth_service,
                mock_publish_service,
                "test-req",
            )

        mock_websocket.accept.assert_called_once()
        mock_websocket.close.assert_called_with(
            code=1011, reason="Upstream connection failed"
        )

    @pytest.mark.asyncio
    async def test_publishes_metadata_on_connect(
        self,
        mock_websocket,
        mock_auth_service,
        mock_publish_service,
        ws_auth_result,
    ):
        """Metadata is published after successful auth."""
        mock_upstream = AsyncMock()
        mock_upstream.close = AsyncMock()
        # Make the relay loop exit immediately
        mock_upstream.__aiter__ = MagicMock(return_value=iter([]))

        from starlette.websockets import WebSocketDisconnect

        mock_websocket.receive.side_effect = WebSocketDisconnect(code=1000)

        with (
            patch(
                "portunus.relay.handler.authenticate_ws",
                return_value=ws_auth_result,
            ),
            patch("portunus.relay.handler.config") as mock_config,
            patch(
                "portunus.relay.handler.ws_connect",
                return_value=mock_upstream,
            ),
        ):
            mock_config.relay.max_message_size = 10485760
            mock_config.relay.max_connection_lifetime = 5

            await handle_ws_connection(
                mock_websocket,
                "v1/responses",
                mock_auth_service,
                mock_publish_service,
                "test-req",
            )

        mock_publish_service.publish_metadata.assert_called_once()
        call_kwargs = mock_publish_service.publish_metadata.call_args[1]
        assert call_kwargs["request_id"] == "test-req"
        assert "account_id" in call_kwargs["principal_info"]
