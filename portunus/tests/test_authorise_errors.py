"""Tests for how /authorise maps service exceptions to HTTP status codes."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus
from portunus.exceptions import ConfigurationError, UpstreamServiceError

SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:test-api-key"
AUTHORISE_BODY = {
    "payload": base64.b64encode(
        json.dumps(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRETTEST",
                    "session_token": "TESTTOKEN",
                },
                "secret_arn": SECRET_ARN,
            }
        ).encode()
    ).decode(),
    "target_host": "api.example.com",
}


@pytest.fixture
def mock_xray():
    segment = MagicMock()
    segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as xray:
        xray.recorder.current_segment.return_value = segment
        yield xray


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=portunus), base_url="http://test"
    ) as http_client:
        yield http_client


class TestAuthoriseErrorMapping:
    @pytest.mark.asyncio
    async def test_upstream_service_error_is_a_503(self, client, mock_xray):
        with patch("portunus.app.auth_service") as auth_service:
            auth_service.authenticate = AsyncMock(
                side_effect=UpstreamServiceError("STS is unavailable")
            )

            response = await client.post("/authorise", json=AUTHORISE_BODY)

        assert response.status_code == 503
        assert response.json() == {
            "message": "STS is unavailable",
            "debug_id": "test-trace-id",
        }

    @pytest.mark.asyncio
    async def test_configuration_error_is_a_500(self, client, mock_xray):
        with patch("portunus.app.auth_service") as auth_service:
            auth_service.authenticate = AsyncMock(
                side_effect=ConfigurationError("AWS region is required")
            )

            response = await client.post("/authorise", json=AUTHORISE_BODY)

        assert response.status_code == 500
        assert response.json()["message"] == "Internal server error"
