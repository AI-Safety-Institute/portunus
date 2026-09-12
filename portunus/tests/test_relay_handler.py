"""Tests for WebSocket relay handler."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from portunus.models import AuthResult, PrincipalInfo
from portunus.relay.auth import WsAuthResult
from portunus.relay.handler import (
    _build_upstream_headers,
    _publish_connection_metadata,
    handle_ws_connection,
)


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


class TestBuildUpstreamHeaders:
    """Tests for the upstream header builder."""

    def test_default_injects_bearer_authorization(self, mock_websocket, auth_result):
        """Without overrides the credential goes in Authorization: Bearer."""
        mock_websocket.headers = {
            "authorization": "Bearer test_payload",
            "user-agent": "test-client",
            "x-portunus-target-host": "localhost",
        }

        headers = _build_upstream_headers(mock_websocket, auth_result)

        assert headers == {
            "Authorization": "Bearer sk-test-key",
            "user-agent": "test-client",
        }

    def test_strips_known_auth_headers(self, mock_websocket, auth_result):
        """Client copies of every known credential header are dropped."""
        mock_websocket.headers = {
            "authorization": "Bearer test_payload",
            "x-api-key": "client-supplied",
            "x-goog-api-key": "client-supplied",
            "api-key": "client-supplied",
            "content-type": "application/json",
        }

        headers = _build_upstream_headers(mock_websocket, auth_result)

        assert headers == {
            "Authorization": "Bearer sk-test-key",
            "content-type": "application/json",
        }

    def test_honours_output_header_and_prefix(self, mock_websocket, auth_result):
        """output_header/output_prefix select the single upstream auth header."""
        auth_result.output_header = "x-goog-api-key"
        auth_result.output_prefix = ""
        mock_websocket.headers = {
            "authorization": "Bearer test_payload",
            "x-goog-api-key": "client-supplied",
            "user-agent": "test-client",
        }

        headers = _build_upstream_headers(mock_websocket, auth_result)

        assert headers == {
            "x-goog-api-key": "sk-test-key",
            "user-agent": "test-client",
        }

    def test_empty_prefix_is_honoured(self, mock_websocket, auth_result):
        """An empty output_prefix means no prefix, not the default."""
        auth_result.output_prefix = ""
        mock_websocket.headers = {}

        headers = _build_upstream_headers(mock_websocket, auth_result)

        assert headers == {"Authorization": "sk-test-key"}

    def test_client_copy_of_custom_output_header_is_dropped(
        self, mock_websocket, auth_result
    ):
        """A client header matching output_header (any case) is not forwarded."""
        auth_result.output_header = "X-Custom-Token"
        mock_websocket.headers = {"x-custom-token": "client-supplied"}

        headers = _build_upstream_headers(mock_websocket, auth_result)

        assert headers == {"X-Custom-Token": "Bearer sk-test-key"}


class TestPublishConnectionMetadata:
    """Tests for upgrade-header logging on connect."""

    @pytest.mark.asyncio
    async def test_logged_upgrade_headers_exclude_credentials(
        self, mock_websocket, mock_publish_service, ws_auth_result
    ):
        """Known credential headers and internal headers are not logged."""
        mock_websocket.headers = {
            "authorization": "Bearer test_payload",
            "x-api-key": "client-supplied",
            "x-goog-api-key": "client-supplied",
            "api-key": "client-supplied",
            "x-portunus-target-host": "localhost",
            "user-agent": "test-client",
        }

        with patch(
            "portunus.relay.handler.log_ws_headers", new=AsyncMock()
        ) as log_mock:
            await _publish_connection_metadata(
                mock_publish_service,
                mock_websocket,
                ws_auth_result,
                "test-req",
                "upstream.example.com",
            )

        log_mock.assert_awaited_once()
        logged_headers = log_mock.await_args_list[0].args[2]
        assert logged_headers == {
            "user-agent": "test-client",
            "authority": "upstream.example.com",
        }

    @pytest.mark.asyncio
    async def test_logged_upgrade_headers_exclude_custom_output_header(
        self, mock_websocket, mock_publish_service, ws_auth_result
    ):
        """A client copy of a custom output header is not logged either."""
        ws_auth_result.auth_result.output_header = "X-Custom-Token"
        mock_websocket.headers = {
            "x-custom-token": "client-supplied",
            "user-agent": "test-client",
        }

        with patch(
            "portunus.relay.handler.log_ws_headers", new=AsyncMock()
        ) as log_mock:
            await _publish_connection_metadata(
                mock_publish_service,
                mock_websocket,
                ws_auth_result,
                "test-req",
                "upstream.example.com",
            )

        logged_headers = log_mock.await_args_list[0].args[2]
        assert "x-custom-token" not in logged_headers
        assert logged_headers["user-agent"] == "test-client"


class TestUpstreamConnectHeaders:
    """The headers handed to the upstream connect call come from the auth result."""

    @pytest.mark.asyncio
    async def test_upstream_connect_uses_output_header(
        self,
        mock_websocket,
        mock_auth_service,
        mock_publish_service,
        ws_auth_result,
    ):
        """output_header/output_prefix on the auth result reach ws_connect."""
        ws_auth_result.auth_result.output_header = "x-api-key"
        ws_auth_result.auth_result.output_prefix = ""
        mock_websocket.headers["x-api-key"] = "client-supplied"

        mock_upstream = AsyncMock()
        mock_upstream.close = AsyncMock()
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
            ) as connect_mock,
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

        sent_headers = connect_mock.call_args.kwargs["additional_headers"]
        assert sent_headers["x-api-key"] == "sk-test-key"
        assert "authorization" not in {k.lower() for k in sent_headers}
