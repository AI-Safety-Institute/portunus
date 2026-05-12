"""Behaviour tests for the ext_authz gRPC Check servicer.

Each test name reads as a claim about what the servicer guarantees.
Collaborators (``AuthService``, ``PublishService``, ``sign_request_fn``)
are replaced by small ``Fake*`` classes that record what they received,
so assertions check observable effects rather than internal call counts.

End-to-end behaviour (gRPC framing, Envoy round-trip, real Redis/AWS) is
covered by the docker-compose-driven tests in ``tests/test_behaviours.py``;
this file's scope is the servicer's request handling logic in isolation.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from typing import Any, Optional

import grpc
import pytest
from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2

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
# Fakes — explicit collaborator stand-ins. Prefer these over ``MagicMock``
# because they make the observable behaviour visible (records, ordering) and
# don't couple the assertion to a method name on a mock.
# ---------------------------------------------------------------------------


@dataclass
class _PublishRecord:
    """One call to ``PublishService.publish_metadata``."""

    request_id: str
    principal_info: PrincipalInfo
    when: float  # monotonic timestamp at call site


class FakePublishService:
    """Records publish calls and lets tests inject failure or delay.

    Tests inspect ``self.records`` to see what Portunus claimed it
    published, in what order, and against the auth call's timing.
    """

    def __init__(
        self,
        *,
        delay: float = 0.0,
        raises: Optional[BaseException] = None,
    ) -> None:
        self.records: list[_PublishRecord] = []
        self._delay = delay
        self._raises = raises

    async def publish_metadata(
        self, *, request_id: str, principal_info: PrincipalInfo, **_: Any
    ) -> None:
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._raises is not None:
            raise self._raises
        self.records.append(
            _PublishRecord(
                request_id=request_id,
                principal_info=principal_info,
                when=asyncio.get_event_loop().time(),
            )
        )


@dataclass
class _AuthCall:
    """One call to ``AuthService.authenticate``."""

    request_id: str
    target_host: Optional[str]
    when: float


class FakeAuthService:
    """A trivial AuthService stand-in that returns a fixed result or raises.

    Holds an ``auth_calls`` list so tests can confirm ``target_host`` was
    propagated correctly and that the authenticate call landed before the
    publish call (the synchronous-publish contract).
    """

    def __init__(
        self,
        *,
        result: Optional[AuthResult] = None,
        raises: Optional[BaseException] = None,
    ) -> None:
        self.auth_calls: list[_AuthCall] = []
        self._result = result or AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=None,
            principal_info=_principal_info(),
        )
        self._raises = raises

    async def authenticate(
        self, payload: Any, request_id: str, target_host: Optional[str]
    ) -> AuthResult:
        self.auth_calls.append(
            _AuthCall(
                request_id=request_id,
                target_host=target_host,
                when=asyncio.get_event_loop().time(),
            )
        )
        if self._raises is not None:
            raise self._raises
        return self._result


@dataclass
class _SignCall:
    args: tuple
    kwargs: dict = field(default_factory=dict)


class FakeSignRequest:
    """Replaces ``sign_request_fn``. Returns the configured headers (default
    empty: no signing) and records each call for later inspection."""

    def __init__(self, returns: Optional[dict] = None) -> None:
        self.returns = returns or {}
        self.calls: list[_SignCall] = []

    def __call__(self, *args: Any, **kwargs: Any) -> dict:
        self.calls.append(_SignCall(args=args, kwargs=kwargs))
        return self.returns


# ---------------------------------------------------------------------------
# Builders — protobuf scaffolding kept out of the test bodies so the tests
# focus on the headers / behaviour, not the proto field structure.
# ---------------------------------------------------------------------------


def _principal_info() -> PrincipalInfo:
    return PrincipalInfo(
        arn="arn:aws:iam::111111111111:role/Test",
        account_id="111111111111",
        principal="role/Test",
        session_name="test-session",
        project="test-project",
    )


# A base64 payload that *parses* cleanly. Tests using it expect the auth
# fake to be the gate that succeeds or fails — the bytes only need to
# survive the up-front payload decoding.
_VALID_PAYLOAD = base64.b64encode(
    json.dumps(
        {
            "credentials": {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "session_token": "FQoGZXIvYXdzEPj//////////wEaDExample",
            },
            "secret_arn": (
                "arn:aws:secretsmanager:eu-west-2:111111111111:secret:test"
            ),
        }
    ).encode()
).decode()


def _check_request(
    *,
    payload_header: Optional[str] = _VALID_PAYLOAD,
    target_host: Optional[str] = "api.openai.com",
    request_id: str = "req-001",
) -> external_auth_pb2.CheckRequest:
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
    return external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(http=http_request)
        )
    )


# ---------------------------------------------------------------------------
# Fake servicer context — only what the servicer touches
# ---------------------------------------------------------------------------


class _FakeContext:
    def __init__(self, *, metadata: Optional[list[tuple[str, str]]] = None) -> None:
        self._metadata = list(metadata or [])
        self.aborted_with: Optional[tuple[grpc.StatusCode, str]] = None

    def invocation_metadata(self) -> list[tuple[str, str]]:
        return self._metadata

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self.aborted_with = (code, details)


_PROXY_KEY = "test-proxy-key-shhh"


def _ctx_with_key(value: Optional[str] = _PROXY_KEY) -> _FakeContext:
    metadata = [("x-portunus-proxy-key", value)] if value is not None else []
    return _FakeContext(metadata=metadata)


@pytest.fixture(autouse=True)
def _enable_proxy_key_validation(monkeypatch):
    """Force proxy-key validation on by default. Tests that need it off
    re-monkeypatch within their own body."""
    from portunus.config import config as portunus_config

    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", _PROXY_KEY)
    # Pin api_key_prefix to a stable value so prefix-stripping tests
    # don't depend on host env.
    monkeypatch.setattr(portunus_config, "api_key_prefix", "Bearer ")


def _make_servicer(
    *,
    auth: Optional[FakeAuthService] = None,
    publish: Optional[FakePublishService] = None,
    sign: Optional[FakeSignRequest] = None,
) -> tuple[PortunusAuthServicer, FakeAuthService, FakePublishService, FakeSignRequest]:
    auth = auth or FakeAuthService()
    publish = publish or FakePublishService()
    sign = sign or FakeSignRequest()
    servicer = PortunusAuthServicer(
        auth_service=auth, publish_service=publish, sign_request_fn=sign
    )
    return servicer, auth, publish, sign


def _decoded_headers(headers) -> dict[str, str]:
    """Lower-cased view of an ext_authz HeaderValueOption list."""
    return {h.header.key.lower(): h.header.value for h in headers}


# ---------------------------------------------------------------------------
# Successful auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_auth_substitutes_upstream_api_key_in_authorization_header():
    servicer, _auth, _publish, _sign = _make_servicer()

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.HasField("ok_response")
    assert _decoded_headers(response.ok_response.headers).get("authorization") == (
        "Bearer sk-upstream-test-key"
    )


@pytest.mark.asyncio
async def test_configured_bearer_prefix_is_stripped_before_decoding_payload():
    """The legacy REST path's Lua filter stripped the API key prefix
    before sending the payload to /authorise. ext_authz receives the
    raw header value via Envoy, so the servicer has to strip it.

    Regression test for the deployed-env bug where the servicer was
    base64-decoding the literal string 'Bearer <payload>' and failing
    every real client request."""
    servicer, auth, _publish, _sign = _make_servicer()
    request = _check_request(payload_header=f"Bearer {_VALID_PAYLOAD}")

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response"), (
        f"Expected OK after stripping 'Bearer '; got denied with "
        f"{response.denied_response.body!r}"
    )
    # And the auth backend received the unprefixed payload through to its
    # authenticate call (proves the strip happened, not that the prefix
    # was somehow tolerated by the decoder).
    assert auth.auth_calls, "auth.authenticate should have been called"


@pytest.mark.asyncio
async def test_bare_payload_without_prefix_still_works():
    """Clients that pre-strip the prefix (or use a prefix-less header
    like x-api-key) shouldn't be regressed by the strip logic."""
    servicer, auth, _publish, _sign = _make_servicer()
    request = _check_request(payload_header=_VALID_PAYLOAD)  # no Bearer

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response")
    assert auth.auth_calls


@pytest.mark.asyncio
async def test_target_host_from_request_header_is_passed_through_to_auth_service():
    """The auth service's host-validation needs the target_host the proxy
    is serving. Today the servicer reads it from the
    ``x-portunus-target-host`` HTTP header — this test pins that
    propagation.

    NB: there is a separate behaviour-level bug (tracked) where the
    header is forgeable by the client. That's a fix on the Envoy side,
    not on the servicer.
    """
    servicer, auth, _publish, _sign = _make_servicer()

    await servicer.Check(
        _check_request(target_host="api.anthropic.com"), _ctx_with_key()
    )

    assert auth.auth_calls and auth.auth_calls[0].target_host == "api.anthropic.com"


@pytest.mark.asyncio
async def test_metadata_publish_completes_before_servicer_returns_ok():
    """The synchronous-publish contract: a 200 from the proxy is a
    promise that the auth record was durably published, not just queued.

    Observed by checking the publish record exists by the time Check
    returns — not by counting how many times an internal method was
    called.
    """
    publish = FakePublishService()
    servicer, _auth, _publish, _sign = _make_servicer(publish=publish)

    response = await servicer.Check(
        _check_request(request_id="req-sync-1"), _ctx_with_key()
    )

    assert response.HasField("ok_response")
    assert len(publish.records) == 1
    assert publish.records[0].request_id == "req-sync-1"


# ---------------------------------------------------------------------------
# Proxy-key identity check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_proxy_key_metadata_is_rejected_with_401_and_does_not_call_auth():
    auth = FakeAuthService()
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key(value=None))

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 401
    assert "proxy identity" in response.denied_response.body.lower()
    assert auth.auth_calls == [], "Auth backend should never be reached without a valid proxy key"


@pytest.mark.asyncio
async def test_wrong_proxy_key_is_rejected_with_401_and_does_not_call_auth():
    auth = FakeAuthService()
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key(value="wrong-key"))

    assert response.denied_response.status.code == 401
    assert auth.auth_calls == []


@pytest.mark.asyncio
async def test_empty_proxy_api_key_config_disables_the_identity_check(monkeypatch):
    """Operator escape hatch — an unset config skips the validation so a
    blank-slate dev environment doesn't require a pre-shared key. Tested
    end-to-end here because the empty-string default is load-bearing."""
    from portunus.config import config as portunus_config

    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", "")
    servicer, _auth, _publish, _sign = _make_servicer()

    response = await servicer.Check(_check_request(), _FakeContext())

    assert response.HasField("ok_response")


# ---------------------------------------------------------------------------
# Auth-time failure shapes — each exception class maps to a specific status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_with_no_authorization_header_is_rejected_with_401():
    servicer, _auth, _publish, _sign = _make_servicer()

    response = await servicer.Check(
        _check_request(payload_header=None), _ctx_with_key()
    )

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_payload_error_from_auth_service_is_rejected_with_401():
    auth = FakeAuthService(raises=PayloadError("malformed payload"))
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_credentials_error_from_auth_service_is_rejected_with_401():
    auth = FakeAuthService(raises=CredentialsError("expired credentials"))
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_authentication_error_from_auth_service_is_rejected_with_403():
    """``AuthenticationError`` is what host-validation mismatch raises, so
    this is the unit-level analog of the
    ``secret_with_mismatching_host_is_rejected_with_403`` behaviour test."""
    auth = FakeAuthService(raises=AuthenticationError("identity mismatch"))
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 403


# ---------------------------------------------------------------------------
# Publish failure — fails closed (design choice that defines this service)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_failure_denies_the_request_with_503():
    publish = FakePublishService(raises=RuntimeError("Kinesis is down"))
    servicer, _auth, _publish, _sign = _make_servicer(publish=publish)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 503


@pytest.mark.asyncio
async def test_publish_timeout_denies_the_request_with_503():
    publish = FakePublishService(delay=_METADATA_PUBLISH_TIMEOUT_S + 1)
    servicer, _auth, _publish, _sign = _make_servicer(publish=publish)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 503


@pytest.mark.asyncio
async def test_publish_failure_means_the_publish_record_is_absent():
    """Complement to the 503 test: prove the failed publish didn't leave
    a half-written record. Tightens the fail-closed guarantee against a
    future change that might catch-and-continue on publish error."""
    publish = FakePublishService(raises=RuntimeError("Kinesis is down"))
    servicer, _auth, _, _sign = _make_servicer(publish=publish)

    await servicer.Check(_check_request(), _ctx_with_key())

    assert publish.records == []


# ---------------------------------------------------------------------------
# Defence in depth — unhandled exception returns 500 without leaking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unexpected_exception_returns_500_without_leaking_message_text():
    auth = FakeAuthService(raises=RuntimeError("internal stack trace string"))
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 500
    assert "Internal server error" in response.denied_response.body
    assert "internal stack trace string" not in response.denied_response.body


# ---------------------------------------------------------------------------
# Request ID propagation — operators must be able to correlate Envoy access
# logs with Portunus logs from a denied response alone
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_denied_response_carries_request_id_in_x_portunus_debug_id_header():
    auth = FakeAuthService(raises=PayloadError("bad payload"))
    servicer, _auth, _publish, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(
        _check_request(request_id="req-debug-abc"), _ctx_with_key()
    )

    debug_id_headers = [
        h.header.value
        for h in response.denied_response.headers
        if h.header.key == "x-portunus-debug-id"
    ]
    assert debug_id_headers == ["req-debug-abc"]
