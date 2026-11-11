"""Tests for WebSocket message logging."""

from unittest.mock import AsyncMock, patch

import pytest

from portunus.relay.logger import (
    enqueue_log,
    log_ws_headers,
    log_ws_message,
    log_ws_summary,
    start_log_queue,
    stop_log_queue,
)


@pytest.fixture
def mock_publish_service():
    """Create a mock PublishService."""
    service = AsyncMock()
    service.publish_request_body = AsyncMock(return_value=True)
    service.publish_response_body = AsyncMock(return_value=True)
    service.publish_request_headers = AsyncMock(return_value=True)
    service.publish_response_headers = AsyncMock(return_value=True)
    return service


class TestLogWsMessage:
    """Tests for log_ws_message function."""

    @pytest.mark.asyncio
    async def test_client_message_publishes_to_request_body(self, mock_publish_service):
        """Client-to-upstream messages go to request-body stream."""
        await log_ws_message(
            mock_publish_service,
            "req-123",
            "client_to_upstream",
            b"hello world",
            0,
            None,
        )

        mock_publish_service.publish_request_body.assert_called_once()
        call_kwargs = mock_publish_service.publish_request_body.call_args[1]
        assert call_kwargs["request_id"] == "req-123"
        assert call_kwargs["body_bytes"] == b"hello world"
        assert call_kwargs["chunk_id"] == 0
        assert call_kwargs["num_chunks"] == 1

    @pytest.mark.asyncio
    async def test_upstream_message_publishes_to_response_body(
        self, mock_publish_service
    ):
        """Upstream-to-client messages go to response-body stream."""
        await log_ws_message(
            mock_publish_service,
            "req-123",
            "upstream_to_client",
            b"response data",
            0,
            None,
        )

        mock_publish_service.publish_response_body.assert_called_once()
        mock_publish_service.publish_request_body.assert_not_called()

    @pytest.mark.asyncio
    async def test_publishes_empty_message(self, mock_publish_service):
        """Empty message published as single empty chunk."""
        await log_ws_message(
            mock_publish_service,
            "req-123",
            "client_to_upstream",
            b"",
            5,
            None,
        )

        mock_publish_service.publish_request_body.assert_called_once()
        call_kwargs = mock_publish_service.publish_request_body.call_args[1]
        assert call_kwargs["body_bytes"] == b""
        assert call_kwargs["num_chunks"] == 1

    @pytest.mark.asyncio
    async def test_chunks_large_message(self, mock_publish_service):
        """Large message is chunked into multiple publish calls."""
        with patch(
            "portunus.relay.logger.chunk_body_data",
            return_value=[b"x" * 100, b"x" * 100, b"x" * 100],
        ):
            await log_ws_message(
                mock_publish_service,
                "req-123",
                "client_to_upstream",
                b"x" * 300,
                0,
                None,
            )

            assert mock_publish_service.publish_request_body.call_count == 3

            for i, call in enumerate(
                mock_publish_service.publish_request_body.call_args_list
            ):
                assert call[1]["chunk_id"] == i
                assert call[1]["num_chunks"] == 3

    @pytest.mark.asyncio
    async def test_handles_publish_error(self, mock_publish_service):
        """Publish errors are logged but don't raise."""
        mock_publish_service.publish_request_body.side_effect = Exception(
            "Kinesis error"
        )

        # Should not raise
        await log_ws_message(
            mock_publish_service,
            "req-123",
            "client_to_upstream",
            b"hello",
            0,
            None,
        )


class TestProjectStamping:
    """Every record the relay publishes carries the caller's project."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("direction", "publish_name"),
        [
            ("client_to_upstream", "publish_request_body"),
            ("upstream_to_client", "publish_response_body"),
        ],
    )
    async def test_every_chunk_of_a_message_carries_project(
        self, mock_publish_service, direction, publish_name
    ):
        """A message split across chunks stamps the project on each chunk."""
        with patch(
            "portunus.relay.logger.chunk_body_data",
            return_value=[b"x" * 100, b"x" * 100],
        ):
            await log_ws_message(
                mock_publish_service, "req-123", direction, b"x" * 200, 0, "alpha"
            )

        calls = getattr(mock_publish_service, publish_name).call_args_list
        assert [call.kwargs["project"] for call in calls] == ["alpha", "alpha"]

    @pytest.mark.asyncio
    async def test_queued_message_carries_project(self, mock_publish_service):
        """The worker-pool path the relay uses keeps the project on the item."""
        await start_log_queue(num_workers=1)
        try:
            await enqueue_log(
                mock_publish_service, "req-123", "client_to_upstream", b"hi", 0, "alpha"
            )
        finally:
            await stop_log_queue()

        kwargs = mock_publish_service.publish_request_body.call_args.kwargs
        assert kwargs["project"] == "alpha"

    @pytest.mark.asyncio
    async def test_upgrade_headers_carry_project(self, mock_publish_service):
        await log_ws_headers(mock_publish_service, "req-123", {"a": "b"}, "alpha")

        kwargs = mock_publish_service.publish_request_headers.call_args.kwargs
        assert kwargs["project"] == "alpha"

    @pytest.mark.asyncio
    async def test_summary_carries_project(self, mock_publish_service):
        await log_ws_summary(mock_publish_service, "req-123", 1, 2, 3.0, "alpha")

        kwargs = mock_publish_service.publish_response_headers.call_args.kwargs
        assert kwargs["project"] == "alpha"
