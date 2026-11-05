"""Tests for the POST /authorise endpoint."""

import uuid
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus
from portunus.models import AuthResult, PrincipalInfo

AUTHORISE_BODY = {"payload": "opaque", "target_host": "api.example.com"}


@contextmanager
def _successful_authentication():
    """Stub the auth and publish services so /authorise returns 200."""
    auth_result = AuthResult(
        api_key="sk-test-key",
        principal_info=PrincipalInfo(
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/session",
            account_id="123456789012",
        ),
    )
    with (
        patch("portunus.app.AuthPayload.from_contents", return_value=MagicMock()),
        patch("portunus.app.auth_service") as auth_service,
        patch("portunus.app.publish_service") as publish_service,
    ):
        auth_service.authenticate = AsyncMock(return_value=auth_result)
        publish_service.publish_metadata = AsyncMock()
        yield publish_service


class TestAuthorise:
    @pytest.mark.asyncio
    async def test_authenticate_timeout_returns_503(self):
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
                    headers={"x-amzn-trace-id": "Root=test-trace-id;Sampled=1"},
                )

        assert resp.status_code == 503
        assert resp.json() == {
            "message": "Authorization timed out. Proxy overloaded.",
            "debug_id": "test-trace-id",
        }

    @pytest.mark.asyncio
    async def test_request_id_is_the_upstream_trace_root(self):
        """A caller-supplied X-Amzn-Trace-Id root becomes the request_id."""
        with _successful_authentication() as publish_service:
            async with AsyncClient(
                transport=ASGITransport(app=portunus), base_url="http://test"
            ) as http:
                resp = await http.post(
                    "/authorise",
                    json=AUTHORISE_BODY,
                    headers={"x-amzn-trace-id": "Root=test-trace-id;Sampled=1"},
                )

        assert resp.status_code == 200
        assert resp.json()["request_id"] == "test-trace-id"
        assert publish_service.publish_metadata.await_args.kwargs["request_id"] == (
            "test-trace-id"
        )

    @pytest.mark.asyncio
    async def test_request_id_is_unique_without_a_trace_header(self):
        """Without an upstream trace id each request gets its own request_id.

        The proxy stamps this id on every audit record for the request and
        returns it as X-Amzn-Trace-Id, so a shared placeholder would collapse
        all requests into one group downstream.
        """
        with _successful_authentication() as publish_service:
            async with AsyncClient(
                transport=ASGITransport(app=portunus), base_url="http://test"
            ) as http:
                first = await http.post("/authorise", json=AUTHORISE_BODY)
                second = await http.post("/authorise", json=AUTHORISE_BODY)

        assert first.status_code == 200 and second.status_code == 200
        request_ids = [first.json()["request_id"], second.json()["request_id"]]
        assert "No-Trace-Id" not in request_ids
        assert len(set(request_ids)) == 2
        for request_id in request_ids:
            uuid.UUID(request_id)
        published = [
            call.kwargs["request_id"]
            for call in publish_service.publish_metadata.await_args_list
        ]
        assert published == request_ids
