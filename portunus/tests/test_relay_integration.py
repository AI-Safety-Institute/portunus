"""Integration tests for WebSocket relay handler.

Uses a real websockets server as the upstream (instead of mocks),
testing the full relay path end-to-end within a single process.
Only AuthService is mocked — the WebSocket relay, logging, and
upstream connection are all exercised for real.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
import websockets

from portunus.models import AuthResult, PrincipalInfo
from portunus.relay.auth import WsAuthResult
from portunus.relay.handler import handle_ws_connection


@pytest.fixture()
def auth_result():
    """Create a test AuthResult."""
    return WsAuthResult(
        auth_result=AuthResult(
            api_key="sk-test-key",
            signing_key=None,
            principal_info=PrincipalInfo(
                arn="arn:aws:sts::123:assumed-role/Test/session",
                account_id="123",
            ),
        ),
        api_key="sk-test-key",
    )


@pytest.fixture()
def publish_service():
    """Mock PublishService — we're testing the relay, not Kinesis."""
    service = AsyncMock()
    service.publish_metadata = AsyncMock(return_value=True)
    service.publish_request_headers = AsyncMock(return_value=True)
    service.publish_response_headers = AsyncMock(return_value=True)
    service.publish_request_body = AsyncMock(return_value=True)
    service.publish_response_body = AsyncMock(return_value=True)
    return service


async def _echo_handler(websocket):
    """Simple echo server for testing."""
    async for message in websocket:
        await websocket.send(message)


async def _close_4008_handler(websocket):
    """Upstream that closes immediately with a non-1000 application code."""
    await websocket.close(code=4008, reason="rate limit")


@pytest_asyncio.fixture()
async def echo_server():
    """Start a real WebSocket echo server on a random port."""
    server = await websockets.serve(_echo_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


@pytest_asyncio.fixture()
async def closing_4008_server():
    """Upstream server that closes with code 4008 on connect."""
    server = await websockets.serve(_close_4008_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


def _make_client_ws(port: int):
    """Create a mock Starlette WebSocket that points at our echo server.

    This simulates what FastAPI gives us — a WebSocket object with
    headers, accept/close/send/receive methods. We use a real
    websockets client connection under the hood but wrap it in
    the Starlette interface that handle_ws_connection expects.
    """
    ws = AsyncMock()
    ws.headers = {
        "authorization": "Bearer test",
        "x-portunus-target-host": "127.0.0.1",
        "x-portunus-target-port": str(port),
        "x-portunus-target-use-tls": "false",
        "user-agent": "test-client",
    }
    ws.scope = {"query_string": b""}

    # Track messages sent to the "client" (i.e., responses from upstream)
    received_by_client: list[str] = []
    messages_to_send: asyncio.Queue[dict] = asyncio.Queue()

    async def accept():
        pass

    async def close(code=1000, reason=None):
        pass

    async def send_text(text):
        received_by_client.append(text)

    async def send_bytes(data):
        received_by_client.append(data)

    async def receive():
        msg = await messages_to_send.get()
        return msg

    ws.accept = accept
    ws.close = close
    ws.send_text = send_text
    ws.send_bytes = send_bytes
    ws.receive = receive
    ws._received_by_client = received_by_client
    ws._messages_to_send = messages_to_send

    return ws


class TestRelayIntegration:
    """Integration tests using a real upstream WebSocket server."""

    @pytest.mark.asyncio
    async def test_messages_relayed_end_to_end(
        self, echo_server, auth_result, publish_service
    ):
        """Messages flow client -> relay -> echo -> relay -> client."""
        port = echo_server
        client_ws = _make_client_ws(port)
        num_messages = 3

        # Queue up messages, but don't disconnect yet — wait for echoes
        for msg in ["hello", "world", "test"]:
            await client_ws._messages_to_send.put(
                {"type": "websocket.receive", "text": msg}
            )

        # Replace send_text to detect when all echoes have arrived,
        # then trigger disconnect
        original_received = client_ws._received_by_client

        async def send_text_then_disconnect(text):
            original_received.append(text)
            if len(original_received) >= num_messages:
                await client_ws._messages_to_send.put(
                    {"type": "websocket.disconnect", "code": 1000}
                )

        client_ws.send_text = send_text_then_disconnect

        with patch(
            "portunus.relay.handler.authenticate_ws",
            return_value=auth_result,
        ):
            await handle_ws_connection(
                client_ws,
                "echo",
                AsyncMock(),
                publish_service,
                "test-req-integration",
            )

        assert client_ws._received_by_client == ["hello", "world", "test"]

    @pytest.mark.asyncio
    async def test_large_message_relayed(
        self, echo_server, auth_result, publish_service
    ):
        """Large messages pass through the relay intact."""
        port = echo_server
        client_ws = _make_client_ws(port)
        large_msg = "x" * 100_000

        await client_ws._messages_to_send.put(
            {"type": "websocket.receive", "text": large_msg}
        )

        received = client_ws._received_by_client

        async def send_text_then_disconnect(text):
            received.append(text)
            await client_ws._messages_to_send.put(
                {"type": "websocket.disconnect", "code": 1000}
            )

        client_ws.send_text = send_text_then_disconnect

        with patch(
            "portunus.relay.handler.authenticate_ws",
            return_value=auth_result,
        ):
            await handle_ws_connection(
                client_ws,
                "echo",
                AsyncMock(),
                publish_service,
                "test-req-large",
            )

        assert len(received) == 1
        assert received[0] == large_msg

    @pytest.mark.asyncio
    async def test_multiple_messages_logged(
        self, echo_server, auth_result, publish_service
    ):
        """Each relayed message triggers a Kinesis publish call."""
        port = echo_server
        client_ws = _make_client_ws(port)
        num_messages = 5

        for i in range(num_messages):
            await client_ws._messages_to_send.put(
                {"type": "websocket.receive", "text": f"msg-{i}"}
            )

        received = client_ws._received_by_client

        async def send_text_then_disconnect(text):
            received.append(text)
            if len(received) >= num_messages:
                await client_ws._messages_to_send.put(
                    {"type": "websocket.disconnect", "code": 1000}
                )

        client_ws.send_text = send_text_then_disconnect

        with patch(
            "portunus.relay.handler.authenticate_ws",
            return_value=auth_result,
        ):
            await handle_ws_connection(
                client_ws,
                "echo",
                AsyncMock(),
                publish_service,
                "test-req-logging",
            )

        # 5 client->upstream + 5 upstream->client = 10 body publishes
        total_body_publishes = (
            publish_service.publish_request_body.call_count
            + publish_service.publish_response_body.call_count
        )
        assert total_body_publishes == 10

        # Metadata published once on connect
        publish_service.publish_metadata.assert_called_once()

        # Summary (response headers) published once on close
        publish_service.publish_response_headers.assert_called_once()

    @pytest.mark.asyncio
    async def test_binary_messages_relayed(
        self, echo_server, auth_result, publish_service
    ):
        """Binary messages are relayed correctly."""
        port = echo_server
        client_ws = _make_client_ws(port)
        binary_data = b"\x00\x01\x02\xff"

        await client_ws._messages_to_send.put(
            {"type": "websocket.receive", "bytes": binary_data}
        )

        received = client_ws._received_by_client

        async def send_bytes_then_disconnect(data):
            received.append(data)
            await client_ws._messages_to_send.put(
                {"type": "websocket.disconnect", "code": 1000}
            )

        client_ws.send_bytes = send_bytes_then_disconnect

        with patch(
            "portunus.relay.handler.authenticate_ws",
            return_value=auth_result,
        ):
            await handle_ws_connection(
                client_ws,
                "echo",
                AsyncMock(),
                publish_service,
                "test-req-binary",
            )

        assert len(received) == 1
        assert received[0] == binary_data

    @pytest.mark.asyncio
    async def test_connection_lifetime_limit(
        self, echo_server, auth_result, publish_service
    ):
        """Connection is closed after max_connection_lifetime."""
        port = echo_server
        client_ws = _make_client_ws(port)

        # Don't send disconnect — let the lifetime limit close it
        async def slow_receive():
            await asyncio.sleep(60)
            return {"type": "websocket.disconnect", "code": 1000}

        client_ws.receive = slow_receive

        with (
            patch(
                "portunus.relay.handler.authenticate_ws",
                return_value=auth_result,
            ),
            patch("portunus.relay.handler.config") as mock_config,
        ):
            mock_config.relay.max_message_size = 10_485_760
            mock_config.relay.max_connection_lifetime = 1  # 1 second
            mock_config.relay.auth_timeout = 5.0

            await handle_ws_connection(
                client_ws,
                "echo",
                AsyncMock(),
                publish_service,
                "test-req-lifetime",
            )

        # Summary should still be published even on timeout
        publish_service.publish_response_headers.assert_called_once()

    @pytest.mark.asyncio
    async def test_upstream_close_code_forwarded_to_client(
        self, closing_4008_server, auth_result, publish_service
    ):
        """A non-1000 upstream close is forwarded to the client, not masked as 1000."""
        port = closing_4008_server
        client_ws = _make_client_ws(port)
        captured_close: dict = {}

        async def capture_close(code=1000, reason=None):
            captured_close["code"] = code
            captured_close["reason"] = reason

        client_ws.close = capture_close

        # The upstream closes immediately on connect; just block client_to_upstream
        # so it doesn't race the close event.
        async def block_forever():
            await asyncio.sleep(60)
            return {"type": "websocket.disconnect", "code": 1000}

        client_ws.receive = block_forever

        with patch(
            "portunus.relay.handler.authenticate_ws",
            return_value=auth_result,
        ):
            await handle_ws_connection(
                client_ws,
                "echo",
                AsyncMock(),
                publish_service,
                "test-req-fwd-code",
            )

        assert captured_close.get("code") == 4008
