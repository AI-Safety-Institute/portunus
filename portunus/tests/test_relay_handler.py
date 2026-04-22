"""Tests for WebSocket relay handler."""

import asyncio
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
                "portunus.relay.handler.websockets.connect",
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
                "portunus.relay.handler.websockets.connect",
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

    @pytest.mark.asyncio
    async def test_outer_cancel_does_not_orphan_relay_tasks(
        self,
        mock_websocket,
        mock_auth_service,
        mock_publish_service,
        ws_auth_result,
    ):
        """Cancelling the connection task cleans up inner relay tasks.

        Regression test: previously, when the outer ``ws_relay`` task
        was cancelled from the lifespan drain path, ``_relay``'s
        ``asyncio.wait`` was interrupted and the ``client_to_upstream``
        / ``upstream_to_client`` tasks were orphaned — they kept
        running against a closing socket. The ``finally`` block in
        ``_relay`` now cancels them and awaits their exit.
        """

        # A real object (not a MagicMock) — MagicMock's handling of
        # magic methods like __aiter__ via attribute assignment is
        # unreliable, so we give _relay a concrete async iterable.
        class HangingUpstream:
            def __init__(self):
                self.close = AsyncMock()

            def __aiter__(self):
                return self

            async def __anext__(self):
                await asyncio.Event().wait()
                raise StopAsyncIteration

        hanging_upstream = HangingUpstream()

        async def fake_connect(*args, **kwargs):
            return hanging_upstream

        # Client receive also hangs, so both inner tasks stay pending.
        client_receive_started = asyncio.Event()

        async def hanging_receive():
            client_receive_started.set()
            await asyncio.Event().wait()
            return {"type": "websocket.receive", "text": "x"}

        mock_websocket.receive = AsyncMock(side_effect=hanging_receive)

        with (
            patch(
                "portunus.relay.handler.authenticate_ws",
                return_value=ws_auth_result,
            ),
            patch("portunus.relay.handler.config") as mock_config,
            patch(
                "portunus.relay.handler.websockets.connect",
                new=fake_connect,
            ),
        ):
            mock_config.relay.max_message_size = 10485760
            mock_config.relay.max_connection_lifetime = 3600

            baseline = {t for t in asyncio.all_tasks()}

            outer = asyncio.create_task(
                handle_ws_connection(
                    mock_websocket,
                    "v1/responses",
                    mock_auth_service,
                    mock_publish_service,
                    "test-req",
                )
            )

            # Wait until the relay has actually started the inner tasks.
            await client_receive_started.wait()

            # Simulate lifespan drain cancelling the outer task.
            outer.cancel()

            # The handler should finish cleanly — no hanging, no unraised
            # CancelledError escaping.
            try:
                await asyncio.wait_for(outer, timeout=5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

            # After the outer task completes, no inner relay tasks
            # created by _relay should still be running in the loop.
            current = asyncio.current_task()
            leftover = [
                t
                for t in asyncio.all_tasks()
                if t not in baseline and t is not current and not t.done()
            ]
            assert not leftover, f"Inner relay tasks were orphaned: {leftover}"
