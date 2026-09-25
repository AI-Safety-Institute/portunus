"""Tests for the POST /authorise endpoint."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus
from portunus.models import AuthResult, PrincipalInfo

IDENTITY_TOKEN_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
ATTRIBUTION_HANDLE = "e3" * 32


def _auth_result(**overrides: object) -> AuthResult:
    fields: dict[str, object] = {
        "api_key": "sk-test-key",
        "principal_info": PrincipalInfo(
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/session",
            account_id="123456789012",
        ),
    }
    fields.update(overrides)
    return AuthResult(**fields)  # type: ignore[arg-type]


async def _authorise(auth_result: AuthResult) -> tuple[int, AsyncMock]:
    """POST /authorise with a canned auth result; returns (status, publish_metadata)."""
    publish_metadata = AsyncMock()
    with (
        patch("portunus.app.AuthPayload.from_contents", return_value=MagicMock()),
        patch(
            "portunus.app.auth_service.authenticate",
            new=AsyncMock(return_value=auth_result),
        ),
        patch("portunus.app.publish_service.publish_metadata", new=publish_metadata),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=portunus), base_url="http://test"
        ) as http:
            resp = await http.post(
                "/authorise",
                json={"payload": "opaque", "target_host": "api.example.com"},
            )
    return resp.status_code, publish_metadata


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


class TestAuthoriseCorrelationIds:
    """A minted credential's jti and handle reach the trace and the metadata record."""

    @pytest.mark.asyncio
    async def test_minted_result_is_annotated_and_published(self, mock_segment):
        status, publish_metadata = await _authorise(
            _auth_result(
                identity_token_id=IDENTITY_TOKEN_ID,
                attribution_handle=ATTRIBUTION_HANDLE,
            )
        )

        assert status == 200
        assert mock_segment.put_annotation.call_args_list == [
            (("identity_token_id", IDENTITY_TOKEN_ID),),
            (("attribution_handle", ATTRIBUTION_HANDLE),),
        ]
        kwargs = publish_metadata.await_args.kwargs
        assert kwargs["identity_token_id"] == IDENTITY_TOKEN_ID
        assert kwargs["attribution_handle"] == ATTRIBUTION_HANDLE

    @pytest.mark.asyncio
    async def test_full_attribution_annotates_only_the_token_id(self, mock_segment):
        status, publish_metadata = await _authorise(
            _auth_result(identity_token_id=IDENTITY_TOKEN_ID)
        )

        assert status == 200
        mock_segment.put_annotation.assert_called_once_with(
            "identity_token_id", IDENTITY_TOKEN_ID
        )
        kwargs = publish_metadata.await_args.kwargs
        assert kwargs["identity_token_id"] == IDENTITY_TOKEN_ID
        assert kwargs["attribution_handle"] is None

    @pytest.mark.asyncio
    async def test_stored_key_result_annotates_nothing(self, mock_segment):
        status, publish_metadata = await _authorise(_auth_result())

        assert status == 200
        mock_segment.put_annotation.assert_not_called()
        kwargs = publish_metadata.await_args.kwargs
        assert kwargs["identity_token_id"] is None
        assert kwargs["attribution_handle"] is None

    @pytest.mark.asyncio
    async def test_no_segment_still_authorises(self):
        with patch("portunus.app.xray_service") as xray:
            xray.recorder.current_segment.return_value = None
            status, publish_metadata = await _authorise(
                _auth_result(identity_token_id=IDENTITY_TOKEN_ID)
            )

        assert status == 200
        assert publish_metadata.await_args.kwargs["identity_token_id"] == (
            IDENTITY_TOKEN_ID
        )
