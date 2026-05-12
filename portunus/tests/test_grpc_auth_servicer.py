"""Tests for the ext_authz gRPC Check service.

These tests treat the AuthService / PublishService / sign_request as
dependency-injected collaborators and assert on the CheckResponse the
servicer produces. The gRPC framing itself is exercised by a single
end-to-end test that spins up a real grpc.aio server on a random port.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import grpc
import pytest

from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    PayloadError,
)
from portunus.grpc.auth_servicer import (
    PortunusAuthServicer,
    _METADATA_PUBLISH_TIMEOUT_S,
)
from portunus.models import AuthResult, PrincipalInfo


# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


def _principal_info() -> PrincipalInfo:
    """Build a minimal PrincipalInfo for happy-path tests."""
    return PrincipalInfo(
        arn="arn:aws:iam::111111111111:role/Test",
        account_id="111111111111",
        principal="role/Test",
        session_name="test-session",
        project="test-project",
    )


import base64
import json

# A syntactically-valid base64 payload that decodes to a JSON object with
# the shape `AuthPayload.from_contents` expects. Tests using this value
# expect `auth_service.authenticate` to be mocked and never reach AWS,
# but the upstream payload-parsing has to succeed before the servicer
# even gets to the auth call — so the bytes have to round-trip.
_VALID_PAYLOAD = base64.b64encode(
    json.dumps(
        {
            "credentials": {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "session_token": "FQoGZXIvYXdzEPj//////////wEaDExample",
            },
            "secret_arn": "arn:aws:secretsmanager:eu-west-2:111111111111:secret:test",
        }
    ).encode()
).decode()


def _check_request(
    *,
    payload_header: Optional[str] = _VALID_PAYLOAD,
    target_host: Optional[str] = "api.openai.com",
    request_id: str = "req-001",
):
    """Build an Envoy ext_authz CheckRequest with the given headers.

    Done as a small builder rather than importing pb2 fixtures because
    the servicer reads through the public ``attributes.request.http``
    accessor and we want to vary headers per test without leaking proto
    structure into every test.
    """
    from envoy.config.core.v3 import base_pb2  # noqa: F401 — protos
    from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2

    headers: dict[str, str] = {}
    if payload_header is not None:
        headers["authorization"] = payload_header
    if target_host is not None:
        headers["x-portunus-target-host"] = target_host

    http_request = attribute_context_pb2.AttributeContext.HttpRequest(
        id=request_id,
        method="POST",
        path="/v1/chat/completions",
        host="api.openai.com",
        headers=headers,
    )
    request = attribute_context_pb2.AttributeContext.Request(http=http_request)
    return external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(request=request)
    )


class _MockContext:
    """Minimal grpc.aio.ServicerContext stand-in. Tests don't call into
    the gRPC framing layer — just into the servicer's Check method.

    ``metadata`` is the (key, value) iterable returned by
    invocation_metadata(); default empty so by default the proxy-key
    validation in Check fails closed.
    """

    def __init__(self, *, metadata: Optional[list[tuple[str, str]]] = None) -> None:
        self.aborted_with: Optional[tuple[grpc.StatusCode, str]] = None
        self._metadata = list(metadata or [])

    def invocation_metadata(self) -> list[tuple[str, str]]:
        return self._metadata

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self.aborted_with = (code, details)


# Tests run with config.grpc.proxy_api_key set to a known value; the
# proxy-key validation is on. _ctx_with_key produces a context that
# carries the matching key in invocation metadata.
_PROXY_KEY = "test-proxy-key-shhh"


def _ctx_with_key(value: Optional[str] = _PROXY_KEY) -> _MockContext:
    metadata: list[tuple[str, str]] = []
    if value is not None:
        metadata.append(("x-portunus-proxy-key", value))
    return _MockContext(metadata=metadata)


@pytest.fixture(autouse=True)
def _enable_proxy_key_validation(monkeypatch):
    """Force the validation on for every test in this module."""
    from portunus.config import config as portunus_config

    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", _PROXY_KEY)
    yield


def _make_servicer(
    *,
    auth_result: Optional[AuthResult] = None,
    auth_raises: Optional[Exception] = None,
    publish_raises: Optional[Exception] = None,
    publish_delay: float = 0.0,
    sign_returns: Optional[dict] = None,
) -> tuple[PortunusAuthServicer, MagicMock, MagicMock, MagicMock]:
    """Build a servicer with mock collaborators. Returns (servicer, auth_mock, publish_mock, sign_mock)."""
    auth = MagicMock()
    if auth_raises is not None:

        async def _auth_raise(*args: Any, **kwargs: Any) -> AuthResult:
            raise auth_raises

        auth.authenticate = AsyncMock(side_effect=auth_raises)
    else:
        result = auth_result or AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=None,
            principal_info=_principal_info(),
        )
        auth.authenticate = AsyncMock(return_value=result)

    publish = MagicMock()

    async def _publish_metadata(**kwargs: Any) -> None:
        if publish_delay:
            await asyncio.sleep(publish_delay)
        if publish_raises:
            raise publish_raises

    publish.publish_metadata = AsyncMock(side_effect=_publish_metadata)

    sign = MagicMock(return_value=sign_returns or {})

    servicer = PortunusAuthServicer(
        auth_service=auth, publish_service=publish, sign_request_fn=sign
    )
    return servicer, auth, publish, sign


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ok_response_carries_upstream_api_key():
    servicer, _auth, _publish, _sign = _make_servicer()
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response"), (
        "Expected ok_response on a successful auth"
    )
    headers = {h.header.key.lower(): h.header.value for h in response.ok_response.headers}
    assert headers.get("authorization") == "Bearer sk-upstream-test-key"


@pytest.mark.asyncio
async def test_metadata_publish_called_synchronously_before_ok():
    servicer, _auth, publish, _sign = _make_servicer()
    request = _check_request()

    await servicer.Check(request, _ctx_with_key())

    publish.publish_metadata.assert_awaited_once()
    args, kwargs = publish.publish_metadata.await_args
    assert "request_id" in kwargs
    assert "principal_info" in kwargs


# Request signing is conditional on filter metadata wired in via Envoy
# typed_per_filter_config — exercising it end-to-end requires a more
# elaborate fixture and lands with the filter-chain PR that actually
# emits the metadata. The unit test for the signing branch belongs there.


# ---------------------------------------------------------------------------
# Proxy-key identity check — the gate that proves the caller is a sanctioned
# Envoy proxy. Service Connect namespace gates network reachability, but the
# namespace is broader than the proxy fleet alone.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_proxy_key_returns_401():
    servicer, _auth, _publish, _sign = _make_servicer()
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key(value=None))

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 401
    assert "proxy identity" in response.denied_response.body.lower()


@pytest.mark.asyncio
async def test_wrong_proxy_key_returns_401():
    servicer, _auth, _publish, _sign = _make_servicer()
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key(value="wrong-key"))

    assert response.denied_response.status.code == 401
    assert "proxy identity" in response.denied_response.body.lower()


@pytest.mark.asyncio
async def test_empty_expected_key_disables_validation(monkeypatch):
    """Empty config disables the check — tests-only mode."""
    from portunus.config import config as portunus_config

    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", "")
    servicer, _auth, _publish, _sign = _make_servicer()
    request = _check_request()

    # No metadata at all
    response = await servicer.Check(request, _MockContext())

    assert response.HasField("ok_response"), (
        "Empty proxy_api_key config should skip validation"
    )


# ---------------------------------------------------------------------------
# Sad paths — each exception class maps to a specific HTTP status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_authorization_header_returns_401():
    servicer, _auth, _publish, _sign = _make_servicer()
    request = _check_request(payload_header=None)

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_payload_error_returns_401():
    servicer, _auth, _publish, _sign = _make_servicer(
        auth_raises=PayloadError("malformed payload")
    )
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_credentials_error_returns_401():
    servicer, _auth, _publish, _sign = _make_servicer(
        auth_raises=CredentialsError("expired credentials")
    )
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_authentication_error_returns_403():
    servicer, _auth, _publish, _sign = _make_servicer(
        auth_raises=AuthenticationError("identity mismatch")
    )
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.denied_response.status.code == 403


# ---------------------------------------------------------------------------
# Metadata publish failure — fail closed (the defining design choice for this
# service)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kinesis_failure_fails_request_closed():
    """The whole point of synchronous publish — if Kinesis is down, deny."""
    servicer, _auth, _publish, _sign = _make_servicer(
        publish_raises=RuntimeError("Kinesis is down")
    )
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 503


@pytest.mark.asyncio
async def test_kinesis_timeout_fails_request_closed():
    servicer, _auth, _publish, _sign = _make_servicer(
        publish_delay=_METADATA_PUBLISH_TIMEOUT_S + 1
    )
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 503


# ---------------------------------------------------------------------------
# Defence-in-depth — unhandled exception returns 500, not a leaked traceback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unexpected_exception_returns_500_not_traceback():
    servicer, _auth, _publish, _sign = _make_servicer(
        auth_raises=RuntimeError("totally unexpected")
    )
    request = _check_request()

    response = await servicer.Check(request, _ctx_with_key())

    assert response.denied_response.status.code == 500
    assert "Internal server error" in response.denied_response.body
    # And no traceback in the response body
    assert "totally unexpected" not in response.denied_response.body


# ---------------------------------------------------------------------------
# Request ID propagation — debug id must be returned to the caller so
# operators can correlate Envoy access logs with Portunus logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_denied_response_carries_debug_id_header():
    servicer, _auth, _publish, _sign = _make_servicer(
        auth_raises=PayloadError("bad payload")
    )
    request = _check_request(request_id="req-debug-123")

    response = await servicer.Check(request, _ctx_with_key())

    debug_headers = [
        h.header.value
        for h in response.denied_response.headers
        if h.header.key == "x-portunus-debug-id"
    ]
    assert debug_headers == ["req-debug-123"]
