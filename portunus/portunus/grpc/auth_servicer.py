"""Envoy ``ext_authz`` v3 ``Check`` service.

Wraps :class:`portunus.services.auth_service.AuthService` so Envoy calls
Portunus via the gRPC ``ext_authz`` filter rather than a REST endpoint.

Contract notes:

1. The auth payload arrives in a request **header**, not the body.
   ``ext_authz`` filters are configured with ``with_request_body``
   set (envoy.yaml) so tenants that require request signing
   (``signing_key`` on the secret) can have ``Content-Digest``
   computed over the buffered body and the RFC 9421 ``Signature`` /
   ``Signature-Input`` headers added before the request is forwarded.
   Tenants without a signing key ignore the body bytes; the buffer
   is short-lived (released after Check returns).

2. The upstream API key is returned via :class:`OkHttpResponse` header
   mutations (``headers``, ``headers_to_remove``). Envoy applies these
   to the request before forwarding upstream.

3. The service is designed for ``failure_mode_allow: false`` on the
   filter side — if Check errors or times out, Envoy returns 5xx rather
   than forwarding unauthenticated requests.

Metadata publish is **synchronous** inside Check. If Kinesis is
unavailable, Check itself fails, so every request that proceeds to
upstream has its principal info recorded.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Callable, Optional

import grpc
from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import status_pb2
from pydantic import ValidationError

from portunus.config import config
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
)
from portunus.grpc.proxy_auth import (
    extract_proxy_key,
    is_valid_proxy_key,
)
from portunus.grpc.proxy_auth import (
    extract_target_host as _extract_target_host,
)
from portunus.models import AuthPayload
from portunus.services.auth_service import AuthService
from portunus.services.publish_service import PublishService
from portunus.services.signing_service import (
    SignableRequest,
    SignatureHeaders,
)
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")

# Header the proxy uses to carry the portunus payload. The Check service
# reads this header from the ext_authz request context.
_DEFAULT_PAYLOAD_HEADER = "authorization"


# Synchronous Kinesis publish timeout. If Kinesis is slower than this,
# the request fails closed.
_METADATA_PUBLISH_TIMEOUT_S = 3

# Bound on the STS / Secrets Manager call inside AuthService.authenticate.
# Without this an unresponsive AWS endpoint stalls every ext_authz call
# until Envoy's own 5s timeout kicks in — at which point the client sees
# a generic Envoy 5xx instead of our 504/DEADLINE_EXCEEDED.
_AUTH_TIMEOUT_S = 5


class PortunusAuthServicer(external_auth_pb2_grpc.AuthorizationServicer):
    """Envoy ext_authz v3 ``AuthorizationServicer`` implementation."""

    def __init__(
        self,
        *,
        auth_service: AuthService,
        publish_service: PublishService,
        sign_request_fn: Callable[..., SignatureHeaders],
    ) -> None:
        self._auth = auth_service
        self._publish = publish_service
        self._sign = sign_request_fn

    async def Check(  # noqa: N802 — proto-defined method name
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> external_auth_pb2.CheckResponse:
        """Handle an Envoy ext_authz Check call.

        Returns ``CheckResponse`` with either ``ok_response`` (allow with
        header mutations) or ``denied_response`` (deny with HTTP status).
        Never raises — failures are reported as ``denied_response`` so
        the Envoy filter's failure_mode_allow contract is unambiguous.
        """
        request_id = self._extract_request_id(request)
        headers = _http_headers(request)

        # Identity check: proxy presents a pre-shared key via gRPC
        # initial_metadata. SC namespace membership is broader than
        # "you are the api-key-proxy", so this is the gate that proves
        # caller identity. With validation disabled (empty expected key)
        # this becomes a no-op — only safe in tests.
        received_proxy_key = extract_proxy_key(context)
        if not is_valid_proxy_key(received_proxy_key, config.grpc.proxy_api_key):
            return _denied(
                code=401,
                body="Missing or invalid proxy identity",
                request_id=request_id,
            )

        try:
            raw_payload = headers.get(_DEFAULT_PAYLOAD_HEADER, "")
            if not raw_payload:
                return _denied(
                    code=401,
                    body="Missing authorization header",
                    request_id=request_id,
                )

            # Strip the configured API key prefix (typically "Bearer ") so
            # the remainder is the bare base64-encoded payload. The legacy
            # REST path stripped this in the Lua filter; the gRPC path
            # gets the raw header value via ext_authz and has to do it
            # here. Tolerate the prefix being absent: clients that send
            # the bare payload still work.
            if config.api_key_prefix and raw_payload.startswith(config.api_key_prefix):
                raw_payload = raw_payload[len(config.api_key_prefix) :]

            # target_host is sent server-side via the gRPC channel's
            # initial_metadata (envoy.yaml ext_authz filter config), NOT
            # via an HTTP header. The matching HTTP header is stripped
            # at the proxy's route_config too as defence in depth. Reading
            # from invocation_metadata closes the forgery path because
            # clients can't reach the gRPC channel.
            target_host = _extract_target_host(context)

            payload = AuthPayload.from_contents(raw_payload, target_host=None)
            try:
                async with asyncio.timeout(_AUTH_TIMEOUT_S):
                    auth_result = await self._auth.authenticate(
                        payload, request_id, target_host
                    )
            except TimeoutError:
                logger.warning(
                    "Auth timeout (%ss) for request_id=%s",
                    _AUTH_TIMEOUT_S,
                    request_id,
                )
                return _denied(
                    code=504,
                    body="Auth backend timeout",
                    request_id=request_id,
                )

            signature_headers: Optional[SignatureHeaders] = None
            content_digest: Optional[str] = None
            if auth_result.signing_key is not None:
                # Tenants with a KMS signing key (Anthropic-style signed
                # requests) need Content-Digest computed over the request
                # body and a Signature / Signature-Input pair derived from
                # it. ext_authz is configured with ``with_request_body``
                # in envoy.yaml so the body reaches this servicer in
                # ``request.attributes.request.http.body``; the
                # SignableRequest is built from the CheckRequest itself
                # rather than via Envoy filter metadata (the legacy Lua
                # path built it client-side; here we just have the same
                # information directly).
                body_bytes = _request_body_bytes(request)
                content_digest = _content_digest(body_bytes)
                try:
                    signable = _signable_request_from_check(
                        request, headers, content_digest, target_host
                    )
                    signature_headers = self._sign(
                        signable,
                        auth_result.signing_key,
                        auth_result.api_key,
                        payload.credentials,
                    )
                except ValidationError as e:
                    logger.error(
                        "Failed to build signable request (request_id=%s): %s",
                        request_id,
                        e,
                    )
                    return _denied(
                        code=500,
                        body="Invalid request signing parameters",
                        request_id=request_id,
                    )

            # Synchronous Kinesis publish — fail-closed if it errors or
            # times out, so every request reaching upstream has its
            # principal info recorded.
            try:
                async with asyncio.timeout(_METADATA_PUBLISH_TIMEOUT_S):
                    published = await self._publish.publish_metadata(
                        request_id=request_id,
                        timestamp=generate_iso_timestamp(),
                        principal_info=auth_result.principal_info.to_dict(),
                        secret_arn=payload.secret_arn,
                    )
                if not published:
                    # publish_metadata returns False (no exception) when
                    # the Kinesis stream isn't configured. Treat as a
                    # fail-closed audit gap rather than silently
                    # admitting the request.
                    logger.critical(
                        "Metadata publish returned False — likely unconfigured stream "
                        "(request_id=%s)",
                        request_id,
                    )
                    return _denied(
                        code=503,
                        body="Audit publish unconfigured — request rejected",
                        request_id=request_id,
                    )
            except (TimeoutError, asyncio.TimeoutError):
                logger.critical(
                    "Metadata publish timed out (request_id=%s)", request_id
                )
                return _denied(
                    code=503,
                    body="Audit publish timed out — request rejected",
                    request_id=request_id,
                )
            except Exception as e:
                logger.critical(
                    "Metadata publish failed (request_id=%s): %s",
                    request_id,
                    e,
                )
                return _denied(
                    code=503,
                    body="Audit publish failed — request rejected",
                    request_id=request_id,
                )

            return _ok(
                api_key=auth_result.api_key,
                signature_headers=signature_headers,
                content_digest=content_digest,
                request_id=request_id,
            )

        except PayloadError as e:
            return _denied(code=401, body=e.message, request_id=request_id)
        except CredentialsError as e:
            return _denied(code=401, body=e.message, request_id=request_id)
        except AuthenticationError as e:
            return _denied(code=403, body=e.message, request_id=request_id)
        except FetchSecretError as e:
            return _denied(
                code=e.http_status_code, body=e.message, request_id=request_id
            )
        except Exception as e:
            # Don't leak internal errors to the customer. Log fully on the
            # server side and return a generic 500.
            logger.exception(
                "Unhandled error in Check (request_id=%s): %s", request_id, e
            )
            return _denied(
                code=500, body="Internal server error", request_id=request_id
            )

    @staticmethod
    def _extract_request_id(request: external_auth_pb2.CheckRequest) -> str:
        """Pull a request ID from Envoy's ext_authz metadata, or mint one.

        Envoy sets ``request.attributes.request.http.id`` to the stream
        ID; surface it directly so log lines correlate with Envoy
        access logs.
        """
        try:
            return request.attributes.request.http.id or str(uuid.uuid4())
        except Exception:
            return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------


def _ok(
    *,
    api_key: str,
    signature_headers: Optional[SignatureHeaders],
    content_digest: Optional[str],
    request_id: str,
) -> external_auth_pb2.CheckResponse:
    """Build a CheckResponse that allows the request with header mutations.

    Mutates the upstream request to:

    - Overwrite ``{api_key_header}`` with the upstream key (configurable;
      default ``authorization``).
    - Remove any client-supplied ``authorization`` so the proxy-shaped
      ``portunus-<payload>`` form doesn't leak to the upstream provider.
    - Add ``Content-Digest``, ``Signature`` and ``Signature-Input`` if
      request signing was required for this provider.
    """
    headers_to_add: list[base_pb2.HeaderValueOption] = []
    headers_to_remove: list[str] = []

    headers_to_add.append(
        base_pb2.HeaderValueOption(
            header=base_pb2.HeaderValue(
                key=config.api_key_header,
                value=f"{config.api_key_prefix}{api_key}",
            ),
            append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
        )
    )
    if config.api_key_header.lower() != "authorization":
        headers_to_remove.append("authorization")

    if content_digest is not None:
        headers_to_add.append(
            base_pb2.HeaderValueOption(
                header=base_pb2.HeaderValue(
                    key="Content-Digest",
                    value=content_digest,
                ),
                append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
            )
        )

    if signature_headers is not None:
        for key, value in signature_headers.items():
            headers_to_add.append(
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(key=key, value=value),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
                )
            )

    return external_auth_pb2.CheckResponse(
        status=status_pb2.Status(code=0),  # OK
        ok_response=external_auth_pb2.OkHttpResponse(
            headers=headers_to_add,
            headers_to_remove=headers_to_remove,
        ),
    )


def _denied(
    *,
    code: int,
    body: str,
    request_id: str,
) -> external_auth_pb2.CheckResponse:
    """Build a CheckResponse that denies the request with a specific HTTP code.

    Envoy returns ``code`` to the downstream client with a JSON-shaped
    error body and the ``x-portunus-error: true`` debug header. The
    JSON shape is ``{"error": {"message": ..., "request_id": ...}}`` —
    matches the legacy Lua-filter contract that downstream clients have
    been parsing since v0.1.
    """
    import json as _json

    json_body = _json.dumps(
        {"error": {"message": body, "request_id": request_id}},
        separators=(",", ":"),
    )
    return external_auth_pb2.CheckResponse(
        status=status_pb2.Status(
            code=grpc.StatusCode.PERMISSION_DENIED.value[0],
            message=body,
        ),
        denied_response=external_auth_pb2.DeniedHttpResponse(
            status=_http_status(code),
            body=json_body,
            headers=[
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(
                        key="content-type",
                        value="application/json",
                    ),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
                ),
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(
                        key=f"x-{config.proxy_header_prefix}-error",
                        value="true",
                    ),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,  # noqa: E501
                ),
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(
                        key="x-portunus-debug-id",
                        value=request_id,
                    ),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
                ),
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _http_headers(
    request: external_auth_pb2.CheckRequest,
) -> dict[str, str]:
    """Flatten Envoy's repeated header field into a case-folded dict."""
    try:
        return {
            k.lower(): v for k, v in request.attributes.request.http.headers.items()
        }
    except Exception:
        return {}


def _request_body_bytes(request: external_auth_pb2.CheckRequest) -> bytes:
    """Read the buffered request body Envoy attaches when with_request_body is on.

    The body is delivered as a string field on the protobuf — Envoy
    encodes it byte-for-byte and we treat it as bytes. Empty when the
    request has no body or buffering is disabled.
    """
    try:
        body = request.attributes.request.http.body
        if isinstance(body, str):
            return body.encode("latin-1")
        return body or b""
    except Exception:
        return b""


def _content_digest(body: bytes) -> str:
    """Compute the RFC 9530 Content-Digest header value over ``body``.

    Format is ``sha-256=:<base64-of-digest>:`` per RFC 9530 §3.1.
    Matches the legacy Lua-filter output bit-for-bit so existing test
    vectors and downstream verifiers continue to pass.
    """
    import base64
    import hashlib

    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def _signable_request_from_check(
    request: external_auth_pb2.CheckRequest,
    headers: dict[str, str],
    content_digest: str,
    target_host: Optional[str],
) -> SignableRequest:
    """Construct the SignableRequest from the ext_authz CheckRequest.

    The legacy Lua filter built the same shape from the proxy-side
    request state. In the gRPC model the ext_authz CheckRequest already
    carries the method, path, and headers; we synthesise the upstream
    URL from ``target_host`` (the trusted server-side value from gRPC
    initial_metadata) plus the request path so a client-forged host
    header cannot redirect the signature to a different origin.

    ``type`` is hard-coded to ``"anthropic"`` because that's the only
    signature provider we currently support; the field exists so a
    second provider with a different signing scheme can be added
    without changing the wire shape.
    """
    http = request.attributes.request.http
    path = getattr(http, "path", "") or "/"
    method = (getattr(http, "method", "") or "POST").upper()
    content_type = headers.get("content-type", "")
    host = target_host or headers.get(":authority") or headers.get("host") or ""
    scheme = "https" if host else "http"
    url = f"{scheme}://{host}{path}" if host else f"http://localhost{path}"
    return SignableRequest(
        type="anthropic",
        url=url,  # type: ignore[arg-type]  # HttpUrl coerces from str
        method=method,
        content_type=content_type,
        content_digest=content_digest,
    )


def _http_status(code: int) -> "http_status_pb2.HttpStatus":
    """Cast an int HTTP code into the proto HttpStatus enum.

    The HttpStatus message lives in ``envoy.type.v3.http_status_pb2`` and
    expects an enum value (``StatusCode``) rather than a raw int. We map
    the handful of codes the Check service emits; anything outside the
    table falls back to 500 InternalServerError.
    """
    code_to_enum = {
        200: http_status_pb2.OK,
        401: http_status_pb2.Unauthorized,
        403: http_status_pb2.Forbidden,
        404: http_status_pb2.NotFound,
        500: http_status_pb2.InternalServerError,
        503: http_status_pb2.ServiceUnavailable,
    }
    enum_value = code_to_enum.get(code, http_status_pb2.InternalServerError)
    return http_status_pb2.HttpStatus(code=enum_value)
