"""Tests for the POST /authorise endpoint."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus


@pytest.fixture
def mock_segment():
    """Patch the X-Ray recorder so the handler sees a segment with a trace id."""
    segment = MagicMock()
    segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as mock:
        mock.recorder.current_segment.return_value = segment
        yield segment


class TestAuthorise:
    @pytest.mark.asyncio
    async def test_authenticate_timeout_returns_503(self, mock_segment):
        """A TimeoutError from authenticate maps to a 503 overloaded response."""
        with (
            patch("portunus.app.AuthPayload.from_contents", return_value=MagicMock()),
            patch(
                "portunus.app.auth_service.authenticate",
                new=AsyncMock(side_effect=TimeoutError("cache read timed out")),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=portunus), base_url="http://test"
            ) as http:
                resp = await http.post(
                    "/authorise",
                    json={"payload": "opaque", "target_host": "api.example.com"},
                )

        assert resp.status_code == 503
        assert resp.json() == {
            "message": "Authorization timed out. Proxy overloaded.",
            "debug_id": "test-trace-id",
        }
        mock_segment.add_exception.assert_called_once()
