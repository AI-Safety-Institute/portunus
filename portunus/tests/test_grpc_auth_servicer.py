"""Behaviour tests for the ext_authz gRPC Check servicer in isolation.

End-to-end behaviour (gRPC framing, Envoy, real Redis/AWS) is covered by
``tests/test_http_proxy_behaviour.py``.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Any, Optional

import grpc
import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import (
    attribute_context_pb2,
    external_auth_pb2,
    external_auth_pb2_grpc,
)
from google.protobuf.json_format import MessageToDict
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from portunus.config import config as portunus_config
from portunus.exceptions import (
    AuthenticationError,
    AuthOverloadedError,
    ConfigurationError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
    UpstreamServiceError,
)
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.models import AuthResult, PrincipalInfo
from portunus.request_context import trace_id_var
from portunus.services import state_service as state_module
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.secrets_service import SecretsService
from portunus.services.state_service import StateService


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
    extra_headers: Optional[dict[str, str]] = None,
    context_extensions: Optional[dict[str, str]] = None,
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
    )
    attrs_kwargs: dict = dict(
        request=attribute_context_pb2.AttributeContext.Request(http=http_request)
    )
    if context_extensions is not None:
        attrs_kwargs["context_extensions"] = context_extensions
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
) -> tuple[PortunusAuthServicer, FakeAuthService]:
    auth = auth or FakeAuthService()
    servicer = PortunusAuthServicer(auth_service=auth)  # type: ignore[arg-type]
    return servicer, auth


@pytest.mark.asyncio
@pytest.mark.parametrize("rpc_trace", [None, "1-00000000-000000000000000000000002"])
@pytest.mark.parametrize("valid_proxy", [False, True])
async def test_envoy_trace_id_precedes_http_header_after_proxy_auth(
    monkeypatch, rpc_trace, valid_proxy
):
    """Trace correlation binds Envoy's own id, and only once the proxy key is good."""
    http_root = "1-00000000-000000000000000000000001"
    seen: list[str | None] = []

    async def record_trace(request, context, request_id, headers):
        seen.append(trace_id_var.get())
        return await authenticate(request, context, request_id, headers)

    metadata = [("x-portunus-proxy-key", _PROXY_KEY if valid_proxy else "invalid")]
    if rpc_trace is not None:
        metadata.append(
            ("x-amzn-trace-id", f"Root={rpc_trace};Parent=0000000000000002;Sampled=1")
        )
    servicer, auth = _make_servicer()
    authenticate = servicer._authenticate
    monkeypatch.setattr(servicer, "_authenticate", record_trace)
    response = await servicer.Check(
        _check_request(
            extra_headers={"x-amzn-trace-id": f"Root={http_root};Sampled=1"}
        ),
        _FakeContext(metadata=metadata),
    )
    if valid_proxy:
        assert response.HasField("ok_response")
        assert len(auth.auth_calls) == 1
        assert seen == [http_root if rpc_trace is None else rpc_trace]
    else:
        # Denied before the handler runs: nothing is bound, nothing authenticates.
        assert response.HasField("denied_response")
        assert not seen and not auth.auth_calls


def _decoded_headers(headers) -> dict[str, str]:
    """Lower-cased view of an ext_authz HeaderValueOption list."""
    return {h.header.key.lower(): h.header.value for h in headers}


# ---------------------------------------------------------------------------
# Successful auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_auth_substitutes_upstream_api_key_in_authorization_header():
    servicer, _auth = _make_servicer()

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
    servicer, auth = _make_servicer()
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
    servicer, auth = _make_servicer()
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
    servicer, auth = _make_servicer()
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
    servicer, auth = _make_servicer()
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
    servicer, auth = _make_servicer()

    await servicer.Check(
        _check_request(target_host="api.anthropic.com"), _ctx_with_key()
    )

    assert auth.auth_calls and auth.auth_calls[0].target_host is None


@pytest.mark.asyncio
async def test_check_attaches_principal_info_and_secret_arn_dynamic_metadata():
    """Auth pass returns principal_info + secret_arn in dynamic_metadata,.

    which ext_proc later surfaces for the audit publish.
    """
    servicer, _auth = _make_servicer()

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
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key(value=None))

    assert response.HasField("denied_response")
    assert response.denied_response.status.code == 401
    assert "proxy identity" in response.denied_response.body.lower()
    assert auth.auth_calls == [], (
        "Auth backend should never be reached without a valid proxy key"
    )


@pytest.mark.asyncio
async def test_wrong_proxy_key_is_rejected_with_401_and_does_not_call_auth():
    auth = FakeAuthService()
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key(value="wrong-key"))

    assert response.denied_response.status.code == 401
    assert auth.auth_calls == []


@pytest.mark.asyncio
async def test_empty_proxy_api_key_config_disables_the_identity_check(monkeypatch):
    """An unset (empty-string) proxy_api_key skips the identity check, so a.

    blank-slate dev environment needs no pre-shared key.
    """
    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", "")
    servicer, _auth = _make_servicer()

    response = await servicer.Check(_check_request(), _FakeContext())

    assert response.HasField("ok_response")


# ---------------------------------------------------------------------------
# Auth-time failure shapes — each exception class maps to a specific status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_with_no_authorization_header_is_rejected_with_401():
    servicer, _auth = _make_servicer()

    response = await servicer.Check(
        _check_request(payload_header=None), _ctx_with_key()
    )

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_payload_error_from_auth_service_is_rejected_with_401():
    auth = FakeAuthService(raises=PayloadError("malformed payload"))
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_credentials_error_from_auth_service_is_rejected_with_401():
    auth = FakeAuthService(raises=CredentialsError("expired credentials"))
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 401


@pytest.mark.asyncio
async def test_authentication_error_from_auth_service_is_rejected_with_403():
    """``AuthenticationError`` (host-validation mismatch) maps to 403."""
    auth = FakeAuthService(raises=AuthenticationError("identity mismatch"))
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 403


# ---------------------------------------------------------------------------
# Defence in depth — unhandled exception returns 500 without leaking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unexpected_exception_returns_500_without_leaking_message_text():
    auth = FakeAuthService(raises=RuntimeError("internal stack trace string"))
    servicer, _auth = _make_servicer(auth=auth)

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
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(
        _check_request(request_id="req-debug-abc"), _ctx_with_key()
    )

    debug_id_headers = [
        h.header.value
        for h in response.denied_response.headers
        if h.header.key == "x-portunus-debug-id"
    ]
    assert debug_id_headers == ["req-debug-abc"]


@pytest.mark.asyncio
async def test_request_id_is_envoys_x_request_id_not_the_stream_id():
    """The request id joins this RPC to the access log and the audit records.

    Both of those carry Envoy's ``x-request-id`` header; ``http.id`` is the
    numeric stream id and appears nowhere else, so the header must win.
    """
    auth = FakeAuthService(raises=PayloadError("bad payload"))
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(
        _check_request(
            request_id="18301084572549365070",
            extra_headers={"x-request-id": "8920f32f-7375-47ba-834b-a6b3a48d9cbf"},
        ),
        _ctx_with_key(),
    )

    debug_id_headers = [
        h.header.value
        for h in response.denied_response.headers
        if h.header.key == "x-portunus-debug-id"
    ]
    assert debug_id_headers == ["8920f32f-7375-47ba-834b-a6b3a48d9cbf"]
    assert json.loads(response.denied_response.body)["error"]["request_id"] == (
        "8920f32f-7375-47ba-834b-a6b3a48d9cbf"
    )


# ---------------------------------------------------------------------------
# Upstream credential header: output_header / output_prefix from the secret.
# ---------------------------------------------------------------------------


def _result_with(**fields: Any) -> AuthResult:
    return AuthResult(
        api_key="sk-upstream-test-key", principal_info=_principal_info(), **fields
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output_header,output_prefix,expected_header,expected_value",
    [
        (None, None, "authorization", "Bearer sk-upstream-test-key"),
        ("", None, "authorization", "Bearer sk-upstream-test-key"),
        ("X-Goog-Api-Key", "", "x-goog-api-key", "sk-upstream-test-key"),
        ("x-api-key", None, "x-api-key", "Bearer sk-upstream-test-key"),
        (None, "Token ", "authorization", "Token sk-upstream-test-key"),
    ],
)
async def test_credential_is_written_to_the_secrets_output_header(
    output_header, output_prefix, expected_header, expected_value
):
    """The credential goes where the secret says, else the configured header.

    A missing or empty output_header falls back to API_KEY_HEADER; a missing
    output_prefix falls back to API_KEY_PREFIX while an empty one means none.
    """
    auth = FakeAuthService(
        result=_result_with(output_header=output_header, output_prefix=output_prefix)
    )
    servicer, _auth = _make_servicer(auth=auth)

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.HasField("ok_response")
    assert _decoded_headers(response.ok_response.headers) == {
        expected_header: expected_value
    }


@pytest.mark.asyncio
async def test_inbound_payload_header_is_removed_only_when_credential_moves():
    moved, _ = _make_servicer(
        auth=FakeAuthService(result=_result_with(output_header="x-api-key"))
    )
    stayed, _ = _make_servicer()

    moved_response = await moved.Check(_check_request(), _ctx_with_key())
    stayed_response = await stayed.Check(_check_request(), _ctx_with_key())

    assert list(moved_response.ok_response.headers_to_remove) == ["authorization"]
    assert list(stayed_response.ok_response.headers_to_remove) == []


@pytest.mark.asyncio
async def test_other_client_headers_are_not_stripped():
    """Provider-specific headers, credential-shaped or not, pass through."""
    servicer, _ = _make_servicer()

    response = await servicer.Check(
        _check_request(
            extra_headers={"x-api-key": "client-own", "anthropic-beta": "x"}
        ),
        _ctx_with_key(),
    )

    assert list(response.ok_response.headers_to_remove) == []


@pytest.mark.asyncio
async def test_upstream_header_name_is_published_for_audit_redaction():
    servicer, _ = _make_servicer(
        auth=FakeAuthService(result=_result_with(output_header="X-Goog-Api-Key"))
    )

    response = await servicer.Check(_check_request(), _ctx_with_key())

    metadata = MessageToDict(response.dynamic_metadata)
    assert metadata["upstream_auth_header"] == "x-goog-api-key"


@pytest.mark.asyncio
async def test_ws_upgrade_is_authenticated_like_any_request():
    servicer, _ = _make_servicer()

    response = await servicer.Check(
        _check_request(extra_headers={"upgrade": "websocket"}), _ctx_with_key()
    )

    assert response.HasField("ok_response")
    assert _decoded_headers(response.ok_response.headers) == {
        "authorization": "Bearer sk-upstream-test-key"
    }


@pytest.mark.asyncio
async def test_fetch_secret_error_uses_its_http_status_code():
    servicer, _ = _make_servicer(
        auth=FakeAuthService(raises=FetchSecretError(404, "Secret not found"))
    )

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 404
    assert json.loads(response.denied_response.body)["error"]["message"] == (
        "Secret not found"
    )


@pytest.mark.asyncio
async def test_mint_dependency_outage_is_rejected_with_503():
    servicer, _ = _make_servicer(auth=FakeAuthService(raises=UpstreamServiceError()))

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 503
    assert json.loads(response.denied_response.body)["error"]["message"] == (
        "Upstream service unavailable"
    )


@pytest.mark.asyncio
async def test_configuration_error_is_a_generic_500():
    """A misconfigured deployment must not leak the configuration detail."""
    servicer, _ = _make_servicer(
        auth=FakeAuthService(raises=ConfigurationError("FEDERATION_* unset"))
    )

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 500
    assert json.loads(response.denied_response.body)["error"]["message"] == (
        "Internal server error"
    )


@pytest.mark.asyncio
async def test_full_auth_capacity_exhaustion_is_shed_with_503():
    servicer, _ = _make_servicer(auth=FakeAuthService(raises=AuthOverloadedError()))

    response = await servicer.Check(_check_request(), _ctx_with_key())

    assert response.denied_response.status.code == 503
    assert "capacity" in response.denied_response.body.lower()


# ---------------------------------------------------------------------------
# Real AuthService + CacheService over counting AWS fakes.
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
    """In-memory Redis command boundary."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> Optional[str]:
        return self._store.get(key)

    async def psetex(self, key: str, ttl: int, value: str) -> bool:
        self._store[key] = value
        return True

    async def ping(self) -> bool:
        return True


_STORED_SECRET = json.dumps({"secret": "sk-upstream-test-key"})


def _far_future_payload() -> str:
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
                    "arn:aws:secretsmanager:eu-west-2:111111111111:secret:cache-test"
                ),
            }
        ).encode()
    ).decode()


def _real_servicer_with_counting_aws(
    redis: Optional[_FakeRedis] = None,
) -> tuple[PortunusAuthServicer, dict]:
    """Wire a real AuthService (real cache) over counting AWS fakes."""
    counters = {"sts": 0, "secrets": 0}
    session = _CountingBotoSession(counters, _STORED_SECRET)
    state = StateService()
    state.redis_client = redis or _FakeRedis()  # type: ignore[assignment]
    auth_service = AuthService(
        secrets_service=SecretsService(boto_session=session),
        cache_service=CacheService(state_service=state),
    )
    servicer = PortunusAuthServicer(auth_service=auth_service)
    return servicer, counters


def _auth_ctx_with_host(target_host: str) -> _FakeContext:
    """Context carrying the trusted target_host via gRPC metadata."""
    return _FakeContext(
        metadata=[
            ("x-portunus-proxy-key", _PROXY_KEY),
            ("x-portunus-target-host", target_host),
        ]
    )


@pytest.mark.asyncio
async def test_repeat_request_is_a_cache_hit_with_no_further_aws_calls():
    servicer, counters = _real_servicer_with_counting_aws()
    payload = _far_future_payload()

    for _ in range(3):
        response = await servicer.Check(
            _check_request(payload_header=payload, target_host=None),
            _auth_ctx_with_host("api.openai.com"),
        )
        assert response.HasField("ok_response"), response

    assert counters == {"sts": 1, "secrets": 1}


@pytest.mark.asyncio
async def test_a_different_target_host_is_a_separate_cache_entry():
    """A result cached for one upstream is never reused for another."""
    servicer, counters = _real_servicer_with_counting_aws()
    payload = _far_future_payload()

    for host in ("api.openai.com", "api.anthropic.com", "api.openai.com"):
        await servicer.Check(
            _check_request(payload_header=payload, target_host=None),
            _auth_ctx_with_host(host),
        )

    assert counters == {"sts": 2, "secrets": 2}


class _PoolWaitExpiredRedis(_FakeRedis):
    """Every lookup finds the blocking pool saturated for the whole wait.

    Raises what redis-py's ``BlockingConnectionPool.get_connection`` raises.
    """

    async def get(self, key: str) -> Optional[str]:
        raise RedisConnectionError("No connection available.") from TimeoutError()


class _RefusedRedis(_FakeRedis):
    """Redis is down: every lookup fails to connect."""

    async def get(self, key: str) -> Optional[str]:
        raise RedisConnectionError(
            "Error 111 connecting to redis:6379. Connection refused."
        )


@pytest.mark.asyncio
async def test_pool_wait_expiry_is_denied_with_504_without_calling_aws():
    """A saturated Redis pool rejects the request rather than stampeding AWS."""
    servicer, counters = _real_servicer_with_counting_aws(_PoolWaitExpiredRedis())

    response = await servicer.Check(
        _check_request(payload_header=_far_future_payload(), target_host=None),
        _auth_ctx_with_host("api.openai.com"),
    )

    assert response.denied_response.status.code == 504
    assert counters == {"sts": 0, "secrets": 0}


@pytest.mark.asyncio
async def test_redis_connect_failure_is_a_miss_and_still_authenticates():
    """Only a pool wait rejects; Redis being unreachable degrades to full auth."""
    servicer, counters = _real_servicer_with_counting_aws(_RefusedRedis())

    response = await servicer.Check(
        _check_request(payload_header=_far_future_payload(), target_host=None),
        _auth_ctx_with_host("api.openai.com"),
    )

    assert response.HasField("ok_response"), response
    assert counters == {"sts": 1, "secrets": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout_stage", ["connect", "read"])
@pytest.mark.parametrize("error_type", [RedisTimeoutError, TimeoutError])
async def test_cache_timeout_denies_without_calling_aws(
    monkeypatch, timeout_stage, error_type
):
    class TimedOutRedis:
        async def ping(self):
            raise error_type("Synthetic connection timeout")

        async def get(self, _key):
            raise error_type("Synthetic cache timeout")

    counters = {"sts": 0, "secrets": 0}
    state = StateService()
    if timeout_stage == "read":
        state.redis_client = TimedOutRedis()  # type: ignore[assignment]
    else:
        monkeypatch.setattr(
            state_module.aioredis.Redis,
            "from_pool",
            staticmethod(lambda _pool: TimedOutRedis()),
        )
    servicer = PortunusAuthServicer(
        auth_service=AuthService(
            secrets_service=SecretsService(
                boto_session=_CountingBotoSession(counters, _STORED_SECRET)
            ),
            cache_service=CacheService(state_service=state),
        ),
    )
    server = grpc.aio.server()
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            response = await external_auth_pb2_grpc.AuthorizationStub(channel).Check(
                _check_request(),
                metadata=[
                    ("x-portunus-proxy-key", _PROXY_KEY),
                    ("x-portunus-target-host", "example.com"),
                ],
                timeout=2,
            )
        assert response.denied_response.status.code == 504
    finally:
        await server.stop(None)

    assert counters == {"sts": 0, "secrets": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key_header,prefix",
    [("authorization", "Bearer "), ("X-Api-Key", ""), ("AUTHORIZATION", "Synthetic ")],
)
@pytest.mark.parametrize("project", [None, "synthetic-project"])
async def test_allow_responses_preserve_identity_and_header_policy_over_grpc(
    monkeypatch, key_header, prefix, project
):
    monkeypatch.setattr(portunus_config, "api_key_header", key_header)
    monkeypatch.setattr(portunus_config, "api_key_prefix", prefix)

    class RequestAuth:
        async def authenticate(self, payload, request_id, target_host):
            return AuthResult(
                api_key=f"synthetic-key-{request_id}",
                principal_info=PrincipalInfo(
                    arn=f"arn:aws:iam::111111111111:role/{request_id}",
                    account_id="111111111111",
                    project=project,
                ),
            )

    servicer = PortunusAuthServicer(auth_service=RequestAuth())  # type: ignore[arg-type]
    server = grpc.aio.server()
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    metadata = [
        ("x-portunus-proxy-key", _PROXY_KEY),
        ("x-portunus-target-host", "example.com"),
    ]
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            stub = external_auth_pb2_grpc.AuthorizationStub(channel)
            requests = [
                _check_request(
                    payload_header=None,
                    request_id=request_id,
                    extra_headers={key_header: f"{prefix}{_VALID_PAYLOAD}"},
                )
                for request_id in ("first", "second")
            ]
            responses = await asyncio.gather(
                *(stub.Check(request, metadata=metadata) for request in requests)
            )
    finally:
        await server.stop(None)

    for request_id, response in zip(("first", "second"), responses, strict=True):
        assert response.HasField("status") and response.status.code == 0
        assert response.WhichOneof("http_response") == "ok_response"
        assert all(
            h.append_action == base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD
            for h in response.ok_response.headers
        )
        assert _decoded_headers(response.ok_response.headers) == {
            key_header.lower(): f"{prefix}synthetic-key-{request_id}"
        }
        assert list(response.ok_response.headers_to_remove) == []
        identity = MessageToDict(response.dynamic_metadata)
        assert (
            identity["principal_info"]
            == PrincipalInfo(
                arn=f"arn:aws:iam::111111111111:role/{request_id}",
                account_id="111111111111",
                project=project,
            ).to_dict()
        )
        assert identity["secret_arn"].endswith(":secret:test")
        assert identity["upstream_auth_header"] == key_header.lower()
