"""Tests for the POST /authorise endpoint."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from portunus.app import AuthorizationResponse, portunus
from portunus.models import AuthResult, PrincipalInfo
from portunus.services.arn_service import parse_identity_from_arn


@pytest.fixture
def mock_segment():
    """Patch the X-Ray recorder so the handler sees a segment with a trace id."""
    segment = MagicMock()
    segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as mock:
        mock.recorder.current_segment.return_value = segment
        yield segment


async def _post_authorise(auth_result: AuthResult) -> dict:
    """Run /authorise with authenticate and the metadata publish stubbed out."""
    payload = MagicMock()
    payload.secret_arn = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:s"
    with (
        patch("portunus.app.AuthPayload.from_contents", return_value=payload),
        patch(
            "portunus.app.auth_service.authenticate",
            new=AsyncMock(return_value=auth_result),
        ),
        patch(
            "portunus.app.publish_service.publish_metadata",
            new=AsyncMock(return_value=True),
        ),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=portunus), base_url="http://test"
        ) as http:
            resp = await http.post(
                "/authorise",
                json={"payload": "opaque", "target_host": "api.example.com"},
            )
    assert resp.status_code == 200
    return resp.json()


class TestAuthorizationResponseModel:
    def test_project_defaults_to_none(self):
        """Older callers that omit project still build a valid response."""
        assert AuthorizationResponse(api_key="k", request_id="r").project is None


class TestAuthorise:
    @pytest.mark.asyncio
    async def test_returns_project_from_principal_info(self, mock_segment):
        """The proxy learns the caller's project from the authorise response."""
        body = await _post_authorise(
            AuthResult(
                api_key="sk-test",
                principal_info=PrincipalInfo(
                    arn="arn:aws:sts::123456789012:assumed-role/UserProfile_me_alpha/s",
                    account_id="123456789012",
                    project="alpha",
                ),
            )
        )
        assert body["project"] == "alpha"
        assert body["request_id"] == "test-trace-id"

    @pytest.mark.asyncio
    async def test_role_without_project_returns_unknown(self, mock_segment):
        """A role name with no project parses to "unknown", which the proxy echoes."""
        principal_info = parse_identity_from_arn(
            "arn:aws:sts::123456789012:assumed-role/PlainRole/session"
        )
        body = await _post_authorise(
            AuthResult(api_key="sk-test", principal_info=principal_info)
        )
        assert body["project"] == "unknown"

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
