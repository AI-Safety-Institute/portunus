"""Tests for the six POST /log/{request_id}/... endpoints.

The proxy stamps the caller's project on each log call as the
``x-portunus-project`` header; each handler must hand it to its publish
builder unchanged, and hand ``None`` through when the header is absent.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus

REQUEST_ID = "req-123"
HEADERS_PAYLOAD = {"timestamp": 1735689600, "headers": {"content-type": "YXBw"}}
TRAILERS_PAYLOAD = {"timestamp": 1735689600, "trailers": {"grpc-status": "MA=="}}

# (path, publish method on portunus.app.publish_service, JSON payload or None for raw)
LOG_ENDPOINTS = [
    (f"/log/{REQUEST_ID}/request/headers", "publish_request_headers", HEADERS_PAYLOAD),
    (f"/log/{REQUEST_ID}/request/body", "publish_request_body", None),
    (
        f"/log/{REQUEST_ID}/request/trailers",
        "publish_request_trailers",
        TRAILERS_PAYLOAD,
    ),
    (
        f"/log/{REQUEST_ID}/response/headers",
        "publish_response_headers",
        HEADERS_PAYLOAD,
    ),
    (f"/log/{REQUEST_ID}/response/body", "publish_response_body", None),
    (
        f"/log/{REQUEST_ID}/response/trailers",
        "publish_response_trailers",
        TRAILERS_PAYLOAD,
    ),
]


@pytest.fixture
def mock_segment():
    """Patch the X-Ray recorder so the handler sees a segment with a trace id."""
    segment = MagicMock()
    segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as mock:
        mock.recorder.current_segment.return_value = segment
        yield segment


async def _post_log(path: str, payload, headers: dict[str, str]):
    async with AsyncClient(
        transport=ASGITransport(app=portunus), base_url="http://test"
    ) as http:
        if payload is None:
            return await http.post(
                path,
                content=b"raw body",
                headers={"content-type": "application/octet-stream", **headers},
            )
        return await http.post(path, json=payload, headers=headers)


class TestLogHandlersProject:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("path", "publish_name", "payload"), LOG_ENDPOINTS)
    async def test_header_reaches_the_publish_builder(
        self, mock_segment, path, publish_name, payload
    ):
        """x-portunus-project is passed through as project=."""
        publish = AsyncMock(return_value=True)
        with patch(f"portunus.app.publish_service.{publish_name}", new=publish):
            resp = await _post_log(path, payload, {"x-portunus-project": "alpha"})

        assert resp.status_code == 200
        publish.assert_awaited_once()
        kwargs = publish.await_args.kwargs
        assert kwargs["request_id"] == REQUEST_ID
        assert kwargs["project"] == "alpha"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("path", "publish_name", "payload"), LOG_ENDPOINTS)
    async def test_missing_header_is_none(
        self, mock_segment, path, publish_name, payload
    ):
        """An older proxy that sends no header still logs, with project=None."""
        publish = AsyncMock(return_value=True)
        with patch(f"portunus.app.publish_service.{publish_name}", new=publish):
            resp = await _post_log(path, payload, {})

        assert resp.status_code == 200
        publish.assert_awaited_once()
        assert publish.await_args.kwargs["project"] is None

    @pytest.mark.asyncio
    async def test_empty_body_chunk_carries_project(self, mock_segment):
        """The empty-body branch builds its single chunk with the project too."""
        publish = AsyncMock(return_value=True)
        with patch("portunus.app.publish_service.publish_request_body", new=publish):
            async with AsyncClient(
                transport=ASGITransport(app=portunus), base_url="http://test"
            ) as http:
                resp = await http.post(
                    f"/log/{REQUEST_ID}/request/body",
                    content=b"",
                    headers={"x-portunus-project": "alpha"},
                )

        assert resp.status_code == 200
        kwargs = publish.await_args.kwargs
        assert kwargs["body_bytes"] == b""
        assert kwargs["project"] == "alpha"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("alpha", "alpha"),
            # ".." is inside the IAM role-name charset, so it passes unchanged.
            ("..", ".."),
            ("a/b", None),
            ("", None),
            ("a" * 100, None),
        ],
    )
    async def test_header_outside_role_name_charset_is_none(
        self, mock_segment, header, expected
    ):
        """A header /authorise could not have produced is treated as absent."""
        publish = AsyncMock(return_value=True)
        with patch("portunus.app.publish_service.publish_request_headers", new=publish):
            resp = await _post_log(
                f"/log/{REQUEST_ID}/request/headers",
                HEADERS_PAYLOAD,
                {"x-portunus-project": header},
            )

        assert resp.status_code == 200
        assert publish.await_args.kwargs["project"] == expected
