"""Behaviour tests for the ext_authz gRPC Check servicer in isolation.

End-to-end behaviour (gRPC framing, Envoy, real Redis/AWS) is covered by
``tests/test_http_proxy_behaviour.py``.
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
    """AuthService stand-in returning a fixed result or raising.

    Records ``auth_calls`` so tests can confirm ``target_host`` propagation.
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
    """Replaces ``sign_request_fn``: returns configured headers (default empty.

    = no signing) and records each call.
    """

    def __init__(self, returns: Optional[dict] = None) -> None:
        self.returns = returns or {}
        self.calls: list[_SignCall] = []

    def __call__(self, *args: Any, **kwargs: Any) -> dict:
        self.calls.append(_SignCall(args=args, kwargs=kwargs))
        return self.returns


# ---------------------------------------------------------------------------
# Builders — protobuf scaffolding kept out of the test bodies.
# ---------------------------------------------------------------------------


def _principal_info() -> PrincipalInfo:
    return PrincipalInfo(
        arn="arn:aws:iam::111111111111:role/Test",
        account_id="111111111111",
        principal="role/Test",
        session_name="test-session",
        project="test-project",
    )


# A base64 payload that parses cleanly; the auth fake is the gate that
# succeeds or fails, so the bytes only need to survive payload decoding.
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
    """Force proxy-key validation on by default; tests needing it off.

    re-monkeypatch in their own body.
    """
    # Config is a module-level Pydantic singleton the servicer reads
    # directly, so DI wouldn't reach the validation call site.
    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", _PROXY_KEY)
    # Pin api_key_prefix so prefix-stripping tests don't depend on host env.
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
    """The servicer must strip the configured ``Bearer `` prefix before.

    base64-decoding the payload, otherwise every real client request fails.
    """
    servicer, auth, _sign = _make_servicer()
    request = _check_request(payload_header=f"Bearer {_VALID_PAYLOAD}")

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response"), (
        f"Expected OK after stripping 'Bearer '; got denied with "
        f"{response.denied_response.body!r}"
    )
    # auth was reached, proving the strip happened (not a tolerant decoder).
    assert auth.auth_calls, "auth.authenticate should have been called"


@pytest.mark.asyncio
async def test_bare_payload_without_prefix_still_works():
    """A prefix-less header (client pre-stripped, or x-api-key) still works."""
    servicer, auth, _sign = _make_servicer()
    request = _check_request(payload_header=_VALID_PAYLOAD)  # no Bearer

    response = await servicer.Check(request, _ctx_with_key())

    assert response.HasField("ok_response")
    assert auth.auth_calls


@pytest.mark.asyncio
async def test_target_host_from_grpc_invocation_metadata_is_passed_to_auth_service():
    """target_host comes from gRPC ``invocation_metadata`` (Envoy-only.

    channel). Reading it from the HTTP header would let a client forge a
    host and pass auth's secret.host check.
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
    """With target_host only in the HTTP header (no gRPC metadata), the.

    servicer passes ``None`` to auth rather than the client-forgeable header.
    Forgery is possible because route_config rewrites land after ext_authz.
    """
    servicer, auth, _sign = _make_servicer()

    await servicer.Check(
        _check_request(target_host="api.anthropic.com"), _ctx_with_key()
    )

    assert auth.auth_calls and auth.auth_calls[0].target_host is None


@pytest.mark.asyncio
async def test_check_attaches_principal_info_and_secret_arn_dynamic_metadata():
    """Auth pass returns principal_info + secret_arn in dynamic_metadata,.

    which ext_proc later surfaces for the audit Firehose publish.
    """
    servicer, _auth, _sign = _make_servicer()

    response = await servicer.Check(
        _check_request(request_id="req-md-1"), _ctx_with_key()
    )

    assert response.HasField("ok_response")
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
    """An unset (empty-string) proxy_api_key skips the identity check, so a.

    blank-slate dev environment needs no pre-shared key.
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
    """``AuthenticationError`` (host-validation mismatch) maps to 403."""
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
# Request signing — two-pass design: ext_authz #1 (auth) + #2 (signing).
# The composite filter gates #2 on the x-portunus-signing-required header set
# by the auth pass; the signing pass re-uses the cached auth result.
# ---------------------------------------------------------------------------


def _signing_ctx(target_host: str | None = "api.openai.com") -> "_FakeContext":
    """GRPC context tagged for the signing pass (ext_authz #2).

    Includes ``x-portunus-target-host`` by default (the signing pass fails
    closed without it). Pass ``target_host=None`` to exercise that path.
    """
    metadata = [
        ("x-portunus-proxy-key", _PROXY_KEY),
        ("x-portunus-pass", "signing"),
    ]
    if target_host is not None:
        metadata.append(("x-portunus-target-host", target_host))
    return _FakeContext(metadata=metadata)


@pytest.mark.asyncio
async def test_auth_pass_for_signing_tenant_sets_signing_required_metadata():
    """Auth pass for a signing tenant sets ``x-portunus-signing-required: true``.

    to dispatch ext_authz #2, and does NOT swap authorization or emit
    signature headers (that's the signing pass).

    The header MUST NOT also be in ``headers_to_remove`` here: Envoy applies
    adds before removes, so listing it in both would strip the value we set.
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
    # authorization is left untouched: the signing pass re-reads the original
    # bearer to recover credentials (cache hit) and installs the upstream key.
    assert "authorization" not in response_headers
    assert "Content-Digest" not in response_headers
    assert "Signature" not in response_headers
    assert sign.calls == []
    assert response_headers["x-portunus-signing-required"] == "true"
    # Not in headers_to_remove here (see docstring: add-before-remove).
    assert "x-portunus-signing-required" not in list(
        response.ok_response.headers_to_remove
    )
    # SECURITY: client-forged signature headers must be stripped on the auth
    # pass; #1's remove runs before #2's add, so legitimate values survive.
    removed = {h.lower() for h in response.ok_response.headers_to_remove}
    assert {
        "content-digest",
        "signature",
        "signature-input",
    } <= removed, f"forged signature headers not stripped on auth pass: {removed}"


@pytest.mark.asyncio
async def test_auth_pass_for_non_signing_tenant_sets_signing_required_false():
    """Tenants without a ``signing_key`` omit the signing-required header so.

    the composite filter skips ext_authz #2. The header is listed in
    ``headers_to_remove`` here (no competing add) to defang a forged copy.
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
    """A signing tenant's WebSocket upgrade is rejected with 400 at ext_authz.

    #1, before the signing pass signs the (empty) upgrade GET body and wastes
    a KMS.Sign call on meaningless signature headers.
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
    # Returned early: no signing-pass dispatch from within _auth_pass.
    assert sign.calls == []


@pytest.mark.asyncio
async def test_auth_pass_allows_ws_upgrade_from_non_signing_tenant():
    """WS upgrade from a non-signing tenant passes through: the 400 fires only.

    when ``signing_required`` is true (guards against over-restricting).
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
    """Signing pass buffers the body, computes Content-Digest, signs, and.

    returns Content-Digest + Signature + Signature-Input, plus installs the
    upstream api_key on authorization (deferred from ext_authz #1).
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
    assert response_headers["authorization"] == "Bearer sk-upstream-test-key"
    assert response_headers["Content-Digest"] == expected_digest
    assert response_headers["Signature"].startswith("sig1=:")
    assert "Signature-Input" in response_headers
    assert len(sign.calls) == 1
    assert sign.calls[0].args[0].content_digest == expected_digest


@pytest.mark.asyncio
async def test_signing_pass_fails_closed_if_auth_no_longer_has_signing_key():
    """If ext_authz #2 fires but the auth result lacks ``signing_key`` (secret.

    edited between passes, or a forged ``x-portunus-signing-required``), fail
    closed with 500 and must NOT invoke KMS.Sign — no forged-flag signature.
    """
    auth = FakeAuthService(
        result=AuthResult(
            api_key="sk-upstream-test-key",
            signing_key=None,
            principal_info=_principal_info(),
        )
    )
    servicer, _auth, sign = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.HasField("denied_response"), response
    assert response.denied_response.status.code == http_status_pb2.InternalServerError
    # SECURITY: KMS.Sign must NOT run without a signing_key (forged-flag defence).
    assert sign.calls == [], "signing pass must not invoke KMS without a signing_key"


@pytest.mark.asyncio
async def test_signing_pass_fails_closed_without_target_host():
    """No ``target_host`` on the signing pass → 500, never sign. The signed.

    ``@target-uri`` must come from the trusted target_host, not the
    client-supplied Host header (a forged Host would redirect the signed URI).
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
    sign = FakeSignRequest(returns={"Signature": "x", "Signature-Input": "y"})
    servicer, _auth, _sign = _make_servicer(auth=auth, sign=sign)

    # target_host=None → no x-portunus-target-host metadata on the context.
    response = await servicer.Check(
        _check_request(body=b"{}"), _signing_ctx(target_host=None)
    )

    assert response.HasField("denied_response"), response
    assert response.denied_response.status.code == http_status_pb2.InternalServerError
    # Crucially, KMS signing was never invoked.
    assert len(sign.calls) == 0


# ---------------------------------------------------------------------------
# Signing-pass error mapping mirrors the auth pass: the same backend failure
# produces the same status code regardless of whether signing is required.
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
    """Host-validation mismatch on the signing pass returns 403 (authn ok,.

    authz failed), not 401.
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
    """A stalled auth backend in the signing pass surfaces as 504, not 500."""
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


@pytest.mark.asyncio
async def test_signing_pass_sheds_with_503_when_signing_capacity_exhausted():
    """``SigningOverloadedError`` from the bounded signer is shed with a 503,.

    not queued and not a generic 500 (each waiter pins its buffered body).
    """
    from portunus.services.signing_service import SigningOverloadedError

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

    class _OverloadedSign(FakeSignRequest):
        def __call__(self, *args: Any, **kwargs: Any) -> dict:
            super().__call__(*args, **kwargs)
            raise SigningOverloadedError("saturated")

    servicer, _auth, _sign = _make_servicer(auth=auth, sign=_OverloadedSign())

    response = await servicer.Check(_check_request(body=b"{}"), _signing_ctx())

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 503
    assert "capacity" in response.denied_response.body.lower()


# ---------------------------------------------------------------------------
# Signing pass rides the Redis cache — no double STS/Secrets round-trip.
#
# The signing pass carries no AWS credentials in dynamic_metadata, so it
# re-derives keys by re-running ``AuthService.authenticate`` (a cache HIT
# in prod). These tests use a REAL AuthService + CacheService (in-memory
# Redis) and count STS / Secrets calls, so a broken cache hit (2× AWS
# traffic per signed request) fails loudly.
# ---------------------------------------------------------------------------


class _CountingAwsClient:
    """Async-context AWS client stand-in; counts the call that matters."""

    def __init__(self, service: str, counters: dict, secret_string: str) -> None:
        self._service = service
        self._counters = counters
        self._secret_string = secret_string

    async def __aenter__(self) -> "_CountingAwsClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def get_caller_identity(self) -> dict:
        self._counters["sts"] += 1
        return {
            "Arn": "arn:aws:sts::111111111111:assumed-role/UserProfile_x_proj/sess-1"
        }

    async def get_secret_value(self, SecretId: str) -> dict:  # noqa: N803 — boto kwarg
        self._counters["secrets"] += 1
        return {"SecretString": self._secret_string}


class _CountingBotoSession:
    """aiobotocore-session stand-in handing out counting clients."""

    def __init__(self, counters: dict, secret_string: str) -> None:
        self._counters = counters
        self._secret_string = secret_string

    def create_client(self, service: str, **_kwargs: Any) -> _CountingAwsClient:
        return _CountingAwsClient(service, self._counters, self._secret_string)


class _FakeRedis:
    """Minimal in-memory Redis: enough for CacheService get/setex/ping."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> Optional[str]:
        return self._store.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self._store[key] = value
        return True

    async def ping(self) -> bool:
        return True


class _FakeStateService:
    def __init__(self) -> None:
        self._redis = _FakeRedis()

    async def acquire_redis_connection(self, *_a: Any, **_k: Any) -> _FakeRedis:
        return self._redis


_SIGNING_SECRET = json.dumps(
    {
        "secret": "sk-upstream-test-key",
        "signing_key": {
            "provider_id": "signingkey_1234abcd",
            "kms_key_arn": "arn:aws:kms:eu-west-2:111111111111:alias/test-key",
        },
    }
)


def _signing_payload() -> str:
    """A bearer payload with a far-future expiration, giving the cache write a.

    positive TTL so the entry is stored (CacheService skips TTL <= 0).
    """
    return base64.b64encode(
        json.dumps(
            {
                "credentials": {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "session_token": "FQoGZXIvYXdzEPj//////////wEaDExample",
                    "expiration": "2099-01-01T00:00:00Z",
                },
                "secret_arn": (
                    "arn:aws:secretsmanager:eu-west-2:111111111111:secret:signing-test"
                ),
            }
        ).encode()
    ).decode()


def _real_servicer_with_counting_aws() -> tuple[PortunusAuthServicer, dict]:
    """Wire a real AuthService (real cache) over counting AWS fakes."""
    from portunus.services.auth_service import AuthService
    from portunus.services.cache_service import CacheService
    from portunus.services.secrets_service import SecretsService

    counters = {"sts": 0, "secrets": 0}
    session = _CountingBotoSession(counters, _SIGNING_SECRET)
    auth_service = AuthService(
        secrets_service=SecretsService(boto_session=session),
        cache_service=CacheService(state_service=_FakeStateService()),  # type: ignore[arg-type]
    )
    servicer = PortunusAuthServicer(
        auth_service=auth_service,
        sign_request_fn=FakeSignRequest(
            returns={"Signature": "sig1=:x:", "Signature-Input": "sig1=()"}
        ),  # type: ignore[arg-type]
    )
    return servicer, counters


def _auth_ctx_with_host(target_host: str) -> _FakeContext:
    """Auth-pass context carrying the trusted target_host via gRPC metadata."""
    return _FakeContext(
        metadata=[
            ("x-portunus-proxy-key", _PROXY_KEY),
            ("x-portunus-target-host", target_host),
        ]
    )


@pytest.mark.asyncio
async def test_signing_pass_cache_hit_issues_sts_and_secrets_once_not_twice():
    """With the SAME trusted ``target_host`` on both passes (as Envoy sends),.

    the signing pass is a cache hit: STS/Secrets are each hit exactly once
    across both passes, not twice.
    """
    servicer, counters = _real_servicer_with_counting_aws()
    payload = _signing_payload()
    host = "api.openai.com"

    # Pass 1 — header-only auth. Populates the cache (miss → 1×STS+Secrets).
    auth_resp = await servicer.Check(
        _check_request(payload_header=payload, target_host=None),
        _auth_ctx_with_host(host),
    )
    assert auth_resp.HasField("ok_response"), auth_resp
    assert counters == {"sts": 1, "secrets": 1}

    # Pass 2 — signing. Same (payload, host) key → cache hit → no AWS call.
    sign_resp = await servicer.Check(
        _check_request(payload_header=payload, target_host=None, body=b'{"m":1}'),
        _signing_ctx(target_host=host),
    )
    assert sign_resp.HasField("ok_response"), sign_resp
    sign_headers = {h.header.key: h.header.value for h in sign_resp.ok_response.headers}
    assert sign_headers.get("Signature", "").startswith("sig1=:")

    # The crux: STS and Secrets each touched exactly once across both passes.
    assert counters == {
        "sts": 1,
        "secrets": 1,
    }, f"signing pass did a fresh AWS round-trip instead of a cache hit: {counters}"


@pytest.mark.asyncio
async def test_divergent_target_host_between_passes_forces_double_sts():
    """A target_host mismatch across passes defeats the host-scoped cache key.

    → cache miss → double STS + Secrets. Documents why both ext_authz filters
    MUST inject the same ``x-portunus-target-host``.
    """
    servicer, counters = _real_servicer_with_counting_aws()
    payload = _signing_payload()

    await servicer.Check(
        _check_request(payload_header=payload, target_host=None),
        _auth_ctx_with_host("api.openai.com"),
    )
    assert counters == {"sts": 1, "secrets": 1}

    # Signing pass sees a DIFFERENT trusted host → different cache key →
    # miss → a second full STS + Secrets round-trip.
    await servicer.Check(
        _check_request(payload_header=payload, target_host=None, body=b'{"m":1}'),
        _signing_ctx(target_host="api.anthropic.com"),
    )
    assert counters == {"sts": 2, "secrets": 2}
