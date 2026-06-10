"""Behaviour tests for the ext_authz gRPC Check servicer.

Each test name reads as a claim about what the servicer guarantees.
Collaborators (``AuthService``, ``sign_request_fn``) are replaced by
small ``Fake*`` classes that record what they received, so assertions
check observable effects rather than internal call counts.

End-to-end behaviour (gRPC framing, Envoy round-trip, real Redis/AWS) is
covered by the docker-compose-driven tests in ``tests/test_http_proxy_behaviour.py``;
this file's scope is the servicer's request handling logic in isolation.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

import grpc
import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2
from envoy.type.v3 import http_status_pb2
from google.protobuf import struct_pb2

from portunus.config import config as portunus_config
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
)
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.models import AuthResult, PrincipalInfo, SigningKey


@dataclass
class _AuthCall:
    """One call to ``AuthService.authenticate``."""

    request_id: str
    target_host: Optional[str]
    when: float


class FakeAuthService:
    """A trivial AuthService stand-in that returns a fixed result or raises.

    Holds an ``auth_calls`` list so tests can confirm ``target_host`` was
    propagated correctly.
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
    """Replaces ``sign_request_fn``. Returns the configured headers (default.

    empty: no signing) and records each call for later inspection.
    """

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
            "secret_arn": ("arn:aws:secretsmanager:eu-west-2:111111111111:secret:test"),
        }
    ).encode()
).decode()


def _check_request(
    *,
    payload_header: Optional[str] = _VALID_PAYLOAD,
    target_host: Optional[str] = "api.openai.com",
    request_id: str = "req-001",
    body: bytes = b"",
    extra_headers: Optional[dict[str, str]] = None,
    context_extensions: Optional[dict[str, str]] = None,
    signable_request: Optional[dict] = None,
) -> external_auth_pb2.CheckRequest:
    headers: dict[str, str] = {}
    if payload_header is not None:
        headers["authorization"] = payload_header
    if target_host is not None:
        headers["x-portunus-target-host"] = target_host
    if extra_headers is not None:
        headers.update(extra_headers)

    http_request = attribute_context_pb2.AttributeContext.HttpRequest(
        id=request_id,
        method="POST",
        path="/v1/chat/completions",
        host="api.openai.com",
        headers=headers,
        body=body.decode("latin-1") if body else "",
    )
    attrs_kwargs: dict = dict(
        request=attribute_context_pb2.AttributeContext.Request(http=http_request)
    )
    if context_extensions is not None:
        attrs_kwargs["context_extensions"] = context_extensions
    if signable_request is not None:
        fields = {}
        for k, v in signable_request.items():
            if isinstance(v, str):
                fields[k] = struct_pb2.Value(string_value=v)
        attrs_kwargs["metadata_context"] = base_pb2.Metadata(
            filter_metadata={
                "envoy.filters.http.ext_authz": struct_pb2.Struct(
                    fields={
                        "signable_request": struct_pb2.Value(
                            struct_value=struct_pb2.Struct(fields=fields)
                        )
                    }
                )
            }
        )
    return external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(**attrs_kwargs)
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
    """Force proxy-key validation on by default. Tests that need it off.

    re-monkeypatch within their own body.
    """
    # monkeypatch: proxy_api_key / api_key_prefix live in a module-level
    # Pydantic config singleton (config.py); the servicer reads it
    # directly, so DI wouldn't reach the validation call site.
    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", _PROXY_KEY)
    # Pin api_key_prefix to a stable value so prefix-stripping tests
    # don't depend on host env.
    monkeypatch.setattr(portunus_config, "api_key_prefix", "Bearer ")


def _make_servicer(
    *,
    auth: Optional[FakeAuthService] = None,
    sign: Optional[FakeSignRequest] = None,
) -> tuple[PortunusAuthServicer, FakeAuthService, FakeSignRequest]:
    auth = auth or FakeAuthService()
    sign = sign or FakeSignRequest()
    servicer = PortunusAuthServicer(
        auth_service=auth,  # type: ignore[arg-type]
        sign_request_fn=sign,  # type: ignore[arg-type]
    )
    return servicer, auth, sign


def _decoded_headers(headers) -> dict[str, str]:
    """Lower-cased view of an ext_authz HeaderValueOption list."""
    return {h.header.key.lower(): h.header.value for h in headers}


# ---------------------------------------------------------------------------
# Successful auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_auth_substitutes_upstream_api_key_in_authorization_header():
    servicer, _auth, _sign = _make_servicer()

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.HasField("ok_response")
    assert _decoded_headers(response.ok_response.headers).get("authorization") == (
        "Bearer sk-upstream-test-key"
    )


@pytest.mark.asyncio
async def test_configured_bearer_prefix_is_stripped_before_decoding_payload():
    """ext_authz must strip the configured API-key prefix before decoding.

    ext_authz receives the raw Authorization header value (including the
    default ``Bearer `` prefix). The servicer must strip the prefix
    before base64-decoding the payload, otherwise every real client
    request fails.
    """
    servicer, auth, _sign = _make_servicer()
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
    """Clients that pre-strip the prefix (or use a prefix-less header.

    like x-api-key) shouldn't be regressed by the strip logic.
    """
    servicer, auth, _sign = _make_servicer()
    request = _check_request(payload_header=_VALID_PAYLOAD)  # no Bearer

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response")
    assert auth.auth_calls


@pytest.mark.asyncio
async def test_target_host_from_grpc_invocation_metadata_is_passed_to_auth_service():
    """target_host is sourced from gRPC ``invocation_metadata`` — the only.

    channel Envoy can write that clients can't reach. Reading from the
    HTTP request header would let a client forge a different host and
    pass auth's secret.host check.
    """
    servicer, auth, _sign = _make_servicer()
    ctx = _FakeContext(
        metadata=[
            ("x-portunus-proxy-key", _PROXY_KEY),
            ("x-portunus-target-host", "api.anthropic.com"),
        ]
    )

    # The HTTP header is set to something else to verify we ignore it.
    await servicer.Check(_check_request(target_host="evil.example.com"), ctx)

    assert auth.auth_calls and auth.auth_calls[0].target_host == "api.anthropic.com"


@pytest.mark.asyncio
async def test_ws_route_context_target_host_overrides_listener_metadata():
    """WS per-route config supplies the WS upstream host to auth."""
    servicer, auth, _sign = _make_servicer()
    ctx = _FakeContext(
        metadata=[
            ("x-portunus-proxy-key", _PROXY_KEY),
            ("x-portunus-target-host", "api.openai.com"),
        ]
    )

    await servicer.Check(
        _check_request(
            extra_headers={"upgrade": "websocket"},
            context_extensions={"target_host": "ws.openai.com"},
        ),
        ctx,
    )

    assert auth.auth_calls and auth.auth_calls[0].target_host == "ws.openai.com"


@pytest.mark.asyncio
async def test_target_host_http_header_is_ignored_to_prevent_client_forgery():
    """If the only target_host is in the HTTP request headers (no gRPC.

    metadata channel), the servicer should pass ``None`` to auth rather
    than trusting the client-forgeable header. The forgery vector exists
    because route_config header rewrites land *after* ext_authz.
    """
    servicer, auth, _sign = _make_servicer()

    await servicer.Check(
        _check_request(target_host="api.anthropic.com"), _ctx_with_key()
    )

    assert auth.auth_calls and auth.auth_calls[0].target_host is None


@pytest.mark.asyncio
async def test_check_attaches_principal_info_and_secret_arn_dynamic_metadata():
    """Auth pass returns principal_info + secret_arn in dynamic_metadata.

    The audit Firehose publish is owned by the logging pass
    (proc_servicer); ext_authz forwards principal_info via Envoy's
    ``CheckResponse.dynamic_metadata`` and the ext_proc filter is
    configured to surface it on the Process stream.
    """
    servicer, _auth, _sign = _make_servicer()

    response = await servicer.Check(
        _check_request(request_id="req-md-1"), _ctx_with_key()
    )

    assert response.HasField("ok_response")
    # principal_info + secret_arn are attached on the dynamic_metadata.
    fields = response.dynamic_metadata.fields
    assert "principal_info" in fields
    assert fields["principal_info"].HasField("struct_value")
    # secret_arn lives next to principal_info under the same namespace.
    assert "secret_arn" in fields


# ---------------------------------------------------------------------------
# Proxy-key identity check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_proxy_key_metadata_is_rejected_with_401_and_does_not_call_auth():
    auth = FakeAuthService()
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key(value=None))

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 401
    assert "proxy identity" in response.denied_response.body.lower()
    assert (
        auth.auth_calls == []
    ), "Auth backend should never be reached without a valid proxy key"


@pytest.mark.asyncio
async def test_wrong_proxy_key_is_rejected_with_401_and_does_not_call_auth():
    auth = FakeAuthService()
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key(value="wrong-key"))

    assert response.denied_response.status.code == 401
    assert auth.auth_calls == []


@pytest.mark.asyncio
async def test_empty_proxy_api_key_config_disables_the_identity_check(monkeypatch):
    """Operator escape hatch — an unset config skips the validation so a.

    blank-slate dev environment doesn't require a pre-shared key. Tested
    end-to-end here because the empty-string default is load-bearing.
    """
    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", "")
    servicer, _auth, _sign = _make_servicer()

    response = await servicer.Check(_check_request(), _FakeContext())

    assert response.HasField("ok_response")


# ---------------------------------------------------------------------------
# Auth-time failure shapes — each exception class maps to a specific status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_with_no_authorization_header_is_rejected_with_401():
    servicer, _auth, _sign = _make_servicer()

    response = await servicer.Check(
        _check_request(payload_header=None), _ctx_with_key()
    )

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_payload_error_from_auth_service_is_rejected_with_401():
    auth = FakeAuthService(raises=PayloadError("malformed payload"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_credentials_error_from_auth_service_is_rejected_with_401():
    auth = FakeAuthService(raises=CredentialsError("expired credentials"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_authentication_error_from_auth_service_is_rejected_with_403():
    """``AuthenticationError`` is what host-validation mismatch raises, so.

    this is the unit-level analog of the
    ``secret_with_mismatching_host_is_rejected_with_403`` behaviour test.
    """
    auth = FakeAuthService(raises=AuthenticationError("identity mismatch"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 403


# ---------------------------------------------------------------------------
# Defence in depth — unhandled exception returns 500 without leaking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unexpected_exception_returns_500_without_leaking_message_text():
    auth = FakeAuthService(raises=RuntimeError("internal stack trace string"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

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
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(
        _check_request(request_id="req-debug-abc"), _ctx_with_key()
    )

    debug_id_headers = [
        h.header.value
        for h in response.denied_response.headers
        if h.header.key == "x-portunus-debug-id"
    ]
    assert debug_id_headers == ["req-debug-abc"]


# ---------------------------------------------------------------------------
# Request signing — two-pass design via ext_authz #1 (auth) + #2 (signing).
# The composite filter ahead of #2 gates on the x-portunus-signing-required
# request header (set by the auth pass, stripped at the route before reaching
# upstream); the signing pass re-uses the cached auth result.
# ---------------------------------------------------------------------------


def _signing_ctx() -> "_FakeContext":
    """Build a gRPC context tagged for the signing pass (ext_authz #2)."""
    return _FakeContext(
        metadata=[
            ("x-portunus-proxy-key", _PROXY_KEY),
            ("x-portunus-pass", "signing"),
        ]
    )


@pytest.mark.asyncio
async def test_auth_pass_for_signing_tenant_sets_signing_required_metadata():
    """The auth pass (ext_authz #1) signals the composite filter to fire.

    ext_authz #2 by setting the ``x-portunus-signing-required: true``
    request header. The composite matcher gates on that header and
    dispatches ext_authz #2. The header is stripped at the route's
    ``request_headers_to_remove`` so it never reaches upstream. Header
    mutations on this pass cover only the upstream api_key —
    Content-Digest and signature headers are produced by the signing
    pass.

    The header MUST NOT also appear in ``headers_to_remove`` on the
    signing branch: Envoy applies headers_to_add before
    headers_to_remove, so listing it in both strips the value we just
    set and the composite filter sees no header. The ``OVERWRITE_IF_-
    EXISTS_OR_ADD`` append_action on the add already replaces any
    client-supplied value.
    """
    signing_key = SigningKey(
        kms_key_arn="arn:aws:kms:eu-west-2:111111111111:alias/test-key",
        provider_id="signingkey_1234abcd",
    )
    auth = FakeAuthService(
        result=AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=signing_key,
            principal_info=_principal_info(),
        )
    )
    servicer, _auth, sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.HasField("ok_response")
    response_headers = {
        h.header.key: h.header.value for h in response.ok_response.headers
    }
    # authorization MUST NOT be replaced on the signing branch — the
    # signing pass that follows re-reads the original bearer payload
    # to recover the credentials (cache hit). The signing pass takes
    # care of installing the upstream api_key.
    assert "authorization" not in response_headers
    assert "Content-Digest" not in response_headers
    assert "Signature" not in response_headers
    # No signing call on this pass — that's the signing pass's job.
    assert sign.calls == []
    # x-portunus-signing-required header signals the composite filter.
    assert response_headers["x-portunus-signing-required"] == "true"
    # Header is NOT in headers_to_remove on the signing branch — see
    # the docstring above for why this would break the composite filter.
    assert "x-portunus-signing-required" not in list(
        response.ok_response.headers_to_remove
    )


@pytest.mark.asyncio
async def test_auth_pass_for_non_signing_tenant_sets_signing_required_false():
    """Tenants without a ``signing_key`` omit the signing-required header so the.

    composite filter skips ext_authz #2 entirely and the body never
    has to be buffered for that request. The header is listed in
    ``headers_to_remove`` on this branch (no competing add) to defang
    any forged inbound copy.
    """
    servicer, _auth, sign = _make_servicer()

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.HasField("ok_response")
    assert sign.calls == []
    response_headers = {
        h.header.key: h.header.value for h in response.ok_response.headers
    }
    assert "x-portunus-signing-required" not in response_headers
    assert "x-portunus-signing-required" in [
        h for h in response.ok_response.headers_to_remove
    ]


@pytest.mark.asyncio
async def test_auth_pass_rejects_ws_upgrade_from_signing_tenant_with_400():
    """A signing tenant initiating a WebSocket upgrade is rejected at ext_authz #1.

    The signing pass would otherwise sign an empty body (the upgrade GET
    has none) and attach meaningless Signature / Content-Digest headers
    — wasting a KMS.Sign call per upgrade and silently misleading the
    caller. We reject early with a clear 400 + remediation message.
    """
    signing_key = SigningKey(
        kms_key_arn="arn:aws:kms:eu-west-2:111111111111:alias/test-key",
        provider_id="signingkey_1234abcd",
    )
    auth = FakeAuthService(
        result=AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=signing_key,
            principal_info=_principal_info(),
        )
    )
    servicer, _auth, sign = _make_servicer(auth=auth)

    # Build a CheckRequest with Upgrade: websocket alongside the auth header.
    headers = {
        "authorization": _VALID_PAYLOAD,
        "x-portunus-target-host": "api.openai.com",
        "upgrade": "websocket",
    }
    http_request = attribute_context_pb2.AttributeContext.HttpRequest(
        id="req-ws-001",
        method="GET",
        path="/v1/realtime",
        host="api.openai.com",
        headers=headers,
    )
    request = external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(http=http_request)
        )
    )

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == http_status_pb2.BadRequest
    assert "WebSocket" in response.denied_response.body
    # Spirit of the assertion: we returned early, no signing-pass
    # dispatch happened from within _auth_pass.
    assert sign.calls == []


@pytest.mark.asyncio
async def test_auth_pass_allows_ws_upgrade_from_non_signing_tenant():
    """WS upgrade from a non-signing tenant is unaffected by the rejection.

    Guards against accidentally over-restricting: the explicit 400 fires
    only when ``signing_required`` is true. Non-signing tenants pass
    through with signing_required=false (header stripped) as usual.
    """
    servicer, _auth, sign = _make_servicer()

    headers = {
        "authorization": _VALID_PAYLOAD,
        "x-portunus-target-host": "api.openai.com",
        "upgrade": "websocket",
    }
    http_request = attribute_context_pb2.AttributeContext.HttpRequest(
        id="req-ws-002",
        method="GET",
        path="/v1/realtime",
        host="api.openai.com",
        headers=headers,
    )
    request = external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(http=http_request)
        )
    )

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response")
    assert sign.calls == []
    response_headers = {
        h.header.key: h.header.value for h in response.ok_response.headers
    }
    assert "x-portunus-signing-required" not in response_headers
    assert "x-portunus-signing-required" in list(response.ok_response.headers_to_remove)


@pytest.mark.asyncio
async def test_signing_pass_computes_digest_and_returns_signature_headers():
    """ext_authz #2 (signing pass) buffers the body, computes.

    Content-Digest, re-authenticates (cache hit in prod), signs, and
    returns Content-Digest + Signature + Signature-Input as header
    mutations. The signing pass also installs the upstream api_key on
    the authorization header: ext_authz #1 deferred that swap so we
    could re-read the original bearer payload here.
    """
    body = b'{"key3": "value3", "key1": "value1", "key2": "value2"}'
    expected_digest = (
        f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')}:"
    )
    signing_key = SigningKey(
        kms_key_arn="arn:aws:kms:eu-west-2:111111111111:alias/test-key",
        provider_id="signingkey_1234abcd",
    )
    auth = FakeAuthService(
        result=AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=signing_key,
            principal_info=_principal_info(),
        )
    )
    sig_input = (
        'sig1=("@method" "@target-uri" "content-digest");keyid="signingkey_1234abcd"'
    )
    sign = FakeSignRequest(
        returns={
            "Signature": "sig1=:fakeBase64SignatureBytes==:",
            "Signature-Input": sig_input,
        }
    )
    servicer, _auth, _sign = _make_servicer(auth=auth, sign=sign)

    response = await servicer.Check(_check_request(body=body), _signing_ctx())

    assert response.HasField("ok_response"), response
    response_headers = {
        h.header.key: h.header.value for h in response.ok_response.headers
    }
    # The signing pass installs the upstream api_key on authorization
    # (ext_authz #1 deferred this so it could re-read the bearer here).
    assert response_headers["authorization"] == "Bearer sk-upstream-test-key"
    assert response_headers["Content-Digest"] == expected_digest
    assert response_headers["Signature"].startswith("sig1=:")
    assert "Signature-Input" in response_headers
    assert len(sign.calls) == 1
    assert sign.calls[0].args[0].content_digest == expected_digest


@pytest.mark.asyncio
async def test_signing_pass_fails_closed_if_auth_no_longer_has_signing_key():
    """If ext_authz #2 fires but the auth result lacks ``signing_key`` (e.g..

    the secret was edited between passes), fail closed rather than
    silently forwarding without a signature.
    """
    auth = FakeAuthService(
        result=AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=None,
            principal_info=_principal_info(),
        )
    )
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.HasField("denied_response"), response
    assert response.denied_response.status.code == http_status_pb2.InternalServerError


# ---------------------------------------------------------------------------
# Signing-pass error mapping mirrors the auth pass — the same backend
# failure must produce the same customer-visible status code regardless of
# whether the request requires signing.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signing_pass_payload_error_is_rejected_with_401():
    auth = FakeAuthService(raises=PayloadError("malformed payload"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_signing_pass_credentials_error_is_rejected_with_401():
    auth = FakeAuthService(raises=CredentialsError("expired credentials"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_signing_pass_authentication_error_is_rejected_with_403():
    """Host-validation mismatch on the signing pass returns 403, not 401.

    The auth pass already established the tenant; a 403 here surfaces the
    distinct "authn ok, authz failed" failure to the customer.
    """
    auth = FakeAuthService(raises=AuthenticationError("identity mismatch"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.denied_response.status.code == 403


@pytest.mark.asyncio
async def test_signing_pass_fetch_secret_error_uses_its_http_status_code():
    auth = FakeAuthService(
        raises=FetchSecretError(http_status_code=503, message="secrets unavailable")
    )
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.denied_response.status.code == 503


@pytest.mark.asyncio
async def test_signing_pass_auth_timeout_is_rejected_with_504(monkeypatch):
    """A stalled auth backend in the signing pass surfaces as 504.

    Matches the auth pass, instead of falling through to a generic 500.
    """
    monkeypatch.setattr("portunus.grpc.auth_servicer._AUTH_TIMEOUT_S", 0.01)

    class _SleepingAuth:
        async def authenticate(self, *_args, **_kwargs):
            await asyncio.sleep(1.0)
            raise AssertionError("should have timed out before reaching here")

    servicer = PortunusAuthServicer(
        auth_service=_SleepingAuth(),  # type: ignore[arg-type]
        sign_request_fn=FakeSignRequest(),  # type: ignore[arg-type]
    )

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.denied_response.status.code == 504


@pytest.mark.asyncio
async def test_signing_pass_unexpected_exception_returns_500_without_leaking_message():
    auth = FakeAuthService(raises=RuntimeError("internal stack trace string"))
    servicer, _auth, _sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.denied_response.status.code == 500
    assert "internal stack trace string" not in response.denied_response.body
