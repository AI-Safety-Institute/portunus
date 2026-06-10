"""Envoy ``ext_authz`` v3 Check servicer.

Two passes share the entry point, discriminated by
``attributes.context_extensions["pass"]``:

- ``auth`` (default): header-only authentication. Returns the upstream
  api_key as a header mutation and sets ``dynamic_metadata`` so the
  composite filter ahead of the signing pass can gate on it.
- ``signing``: re-authenticates (cache hit), computes Content-Digest
  over the buffered body, and returns the RFC 9421 Signature headers.

Audit metadata is published asynchronously from the ext_proc logging
pass via ``CheckResponse.dynamic_metadata``, so Firehose writes stay off
the auth-latency critical path.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import uuid
from typing import Any, Callable, Dict, Optional

import grpc
from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.protobuf import struct_pb2
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
from portunus.services.signing_service import (
    SignableRequest,
    SignatureHeaders,
)

logger = logging.getLogger("api.access")


# Bound the STS / Secrets Manager call below Envoy's 5s ext_authz deadline so
# a stalled AWS endpoint surfaces as a structured 504 from Portunus.
_AUTH_TIMEOUT_S = 4.0


class PortunusAuthServicer(external_auth_pb2_grpc.AuthorizationServicer):
    """Envoy ext_authz v3 ``AuthorizationServicer`` implementation."""

    def __init__(
        self,
        *,
        auth_service: AuthService,
        sign_request_fn: Callable[..., SignatureHeaders],
    ) -> None:
        self._auth = auth_service
        self._sign = sign_request_fn

    async def Check(  # noqa: N802 — proto-defined method name
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> external_auth_pb2.CheckResponse:
        """Handle an Envoy ext_authz Check call.

        Never raises — failures are reported as ``denied_response``.
        """
        request_id = self._extract_request_id(request)

        received_proxy_key = extract_proxy_key(context)
        if not is_valid_proxy_key(received_proxy_key, config.grpc.proxy_api_key):
            return _denied(
                code=401,
                body="Missing or invalid proxy identity",
                request_id=request_id,
            )

        pass_name = _extract_pass(context)
        if pass_name == "signing":
            return await self._signing_pass(request, context, request_id)
        return await self._auth_pass(request, context, request_id)

    async def _auth_pass(
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
        request_id: str,
    ) -> external_auth_pb2.CheckResponse:
        """Header-only auth. Sets dynamic_metadata for the signing-pass gate."""
        headers = _http_headers(request)
        try:
            raw_payload = headers.get(config.api_key_header.lower(), "")
            if not raw_payload:
                return _denied(
                    code=401,
                    body="Missing authorization header",
                    request_id=request_id,
                )

            if config.api_key_prefix and raw_payload.startswith(config.api_key_prefix):
                raw_payload = raw_payload[len(config.api_key_prefix) :]

            # target_host comes from route context or gRPC initial_metadata
            # (both Envoy-controlled), never from client-controllable headers.
            target_host = _extract_target_host_for_check(request, context)

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

            # If a signing pass will follow, defer the authorization
            # replacement to it. ext_authz #2 re-reads the bearer payload
            # from the authorization header to recover the original
            # credentials (cache hit), so we must NOT clobber the
            # header here on the signing branch.
            signing_required = auth_result.signing_key is not None

            # Reject WS upgrade from signing tenants explicitly: the signing pass
            # would otherwise sign an empty body (the upgrade GET has none) and
            # attach meaningless headers, wasting a KMS.Sign call per upgrade and
            # silently misleading the caller. No provider supports signed WS today.
            is_ws_upgrade = headers.get("upgrade", "").lower() == "websocket"
            if signing_required and is_ws_upgrade:
                return _denied(
                    code=400,
                    body=(
                        "Request signing is not currently supported for WebSocket "
                        "connections. Either remove the signing_key from your tenant "
                        "secret to use WebSocket, or use HTTPS for signed requests."
                    ),
                    request_id=request_id,
                )
            return _ok(
                api_key=None if signing_required else auth_result.api_key,
                signature_headers=None,
                content_digest=None,
                request_id=request_id,
                signing_required=signing_required,
                principal_info=auth_result.principal_info.to_dict(),
                secret_arn=payload.secret_arn,
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
            # Log type(e).__name__ only — boto / pydantic / wsproto messages
            # can carry payload bytes.
            logger.error(
                "Unhandled error in Check (request_id=%s): %s",
                request_id,
                type(e).__name__,
            )
            return _denied(
                code=500, body="Internal server error", request_id=request_id
            )

    async def _signing_pass(
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
        request_id: str,
    ) -> external_auth_pb2.CheckResponse:
        """Buffered-body pass that computes Content-Digest and signs.

        Re-authenticates to recover ``signing_key`` / ``api_key`` /
        credentials; the auth result is cached in Redis from the first
        pass so this is a cache hit, not a fresh STS round-trip.
        Carrying AWS credentials via dynamic_metadata would leak them
        to every downstream filter, so we use a cache hit instead.

        Backend-error mapping mirrors ``_auth_pass`` so the same failure
        produces the same customer-visible status code regardless of
        whether the request requires signing.
        """
        try:
            headers = _http_headers(request)
            raw_payload = headers.get(config.api_key_header.lower(), "")
            if config.api_key_prefix and raw_payload.startswith(config.api_key_prefix):
                raw_payload = raw_payload[len(config.api_key_prefix) :]
            target_host = _extract_target_host_for_check(request, context)
            payload = AuthPayload.from_contents(raw_payload, target_host=None)
            try:
                async with asyncio.timeout(_AUTH_TIMEOUT_S):
                    auth_result = await self._auth.authenticate(
                        payload, request_id, target_host
                    )
            except TimeoutError:
                logger.warning(
                    "Auth timeout (%ss) in signing pass for request_id=%s",
                    _AUTH_TIMEOUT_S,
                    request_id,
                )
                return _denied(
                    code=504,
                    body="Auth backend timeout",
                    request_id=request_id,
                )

            if auth_result.signing_key is None:
                # Composite-filter contract violation: signing pass invoked
                # without a signing key. Fail closed.
                logger.error(
                    "Signing pass invoked but auth_result has no signing_key "
                    "(request_id=%s)",
                    request_id,
                )
                return _denied(
                    code=500,
                    body="Signing misconfiguration",
                    request_id=request_id,
                )

            body_bytes = _request_body_bytes(request)
            content_digest = _content_digest(body_bytes)
            try:
                signable = _signable_request_from_check(
                    request, headers, content_digest, target_host
                )
                # ``sign_request`` is sync boto3 (KMS.Sign is a blocking
                # HTTPS round-trip). Offload to a worker thread so the
                # event loop stays free for other ext_authz / ext_proc
                # streams while KMS round-trips (~50ms p50, &gt;1s tail).
                signature_headers = await asyncio.to_thread(
                    self._sign,
                    signable,
                    auth_result.signing_key,
                    auth_result.api_key,
                    payload.credentials,
                )
            except ValidationError as e:
                logger.error(
                    "Failed to build signable request (request_id=%s): %s",
                    request_id,
                    type(e).__name__,
                )
                return _denied(
                    code=500,
                    body="Invalid request signing parameters",
                    request_id=request_id,
                )

            # Replace authorization with the upstream api_key here, not
            # in ext_authz #1: this servicer needs the original bearer
            # payload to re-authenticate (cache hit on the same Redis
            # entry), so ext_authz #1 deferred the swap when it saw a
            # signing_key on the auth result.
            return _ok(
                api_key=auth_result.api_key,
                signature_headers=signature_headers,
                content_digest=content_digest,
                request_id=request_id,
                signing_required=None,
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
            logger.error(
                "Unhandled error in signing pass (request_id=%s): %s",
                request_id,
                type(e).__name__,
            )
            return _denied(
                code=500,
                body="Signing failed",
                request_id=request_id,
            )

    @staticmethod
    def _extract_request_id(request: external_auth_pb2.CheckRequest) -> str:
        """Pull a request ID from Envoy's ext_authz metadata, or mint one."""
        try:
            return request.attributes.request.http.id or str(uuid.uuid4())
        except Exception:
            return str(uuid.uuid4())


def _ok(
    *,
    api_key: Optional[str],
    signature_headers: Optional[SignatureHeaders],
    content_digest: Optional[str],
    request_id: str,
    signing_required: Optional[bool],
    principal_info: Optional[Dict[str, Any]] = None,
    secret_arn: Optional[str] = None,
) -> external_auth_pb2.CheckResponse:
    """Build a CheckResponse that allows the request with header mutations."""
    headers_to_add: list[base_pb2.HeaderValueOption] = []
    headers_to_remove: list[str] = []

    if api_key is not None:
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

    # ext_authz #1 is the single source of truth for signing-required.
    # Envoy applies headers_to_add BEFORE headers_to_remove, so listing
    # the header in both — as the previous version did — strips the
    # value we just set and the composite filter downstream never
    # dispatches the signing pass. ``OVERWRITE_IF_EXISTS_OR_ADD``
    # already replaces any client-supplied value, so only strip on the
    # non-signing branch where we don't re-add it ourselves.
    # Strip any client-forged signature headers on the auth pass.
    # Doing this at the ext_authz layer (not the route's
    # request_headers_to_remove) preserves the legitimate values
    # ext_authz #2 adds on the signing branch — Envoy applies ext_authz
    # mutations in order, so #1's remove runs before #2's add.
    if signing_required is not None:
        headers_to_remove.extend(("content-digest", "signature", "signature-input"))

    if signing_required is not None:
        if signing_required:
            headers_to_add.append(
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(
                        key="x-portunus-signing-required",
                        value="true",
                    ),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
                )
            )
        else:
            headers_to_remove.append("x-portunus-signing-required")

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

    kwargs: Dict[str, Any] = {
        "status": status_pb2.Status(code=0),
        "ok_response": external_auth_pb2.OkHttpResponse(
            headers=headers_to_add,
            headers_to_remove=headers_to_remove,
        ),
    }
    if principal_info is not None or secret_arn is not None:
        dyn = struct_pb2.Struct()
        if principal_info is not None:
            dyn.update({"principal_info": principal_info})
        if secret_arn is not None:
            dyn.update({"secret_arn": secret_arn})
        kwargs["dynamic_metadata"] = dyn
    return external_auth_pb2.CheckResponse(**kwargs)


def _denied(
    *,
    code: int,
    body: str,
    request_id: str,
) -> external_auth_pb2.CheckResponse:
    """Build a CheckResponse denying the request with a specific HTTP code.

    Body shape ``{"error": {"message": ..., "request_id": ...}}`` is a
    stable client contract — do not change.
    """
    json_body = json.dumps(
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


def _extract_pass(context: grpc.aio.ServicerContext) -> str:
    """Read the ext_authz pass discriminator from gRPC ``initial_metadata``."""
    try:
        metadata = context.invocation_metadata() or ()
        for item in metadata:
            # Unpack explicitly: mypy can't narrow ``Metadatum`` when the
            # fallback is an empty tuple.
            key: str = item[0]
            value = item[1]
            if key.lower() == "x-portunus-pass":
                return value if isinstance(value, str) else value.decode("utf-8")
    except Exception as e:
        logger.warning("Failed to read x-portunus-pass metadata: %s", type(e).__name__)
    return "auth"


def _extract_context_extension(
    request: external_auth_pb2.CheckRequest, key: str
) -> Optional[str]:
    """Read an Envoy ext_authz per-route context extension."""
    try:
        value = request.attributes.context_extensions.get(key, "")
        return value or None
    except Exception:
        return None


def _extract_target_host_for_check(
    request: external_auth_pb2.CheckRequest,
    context: grpc.aio.ServicerContext,
) -> Optional[str]:
    """Prefer route-specific target_host over listener initial_metadata."""
    return _extract_context_extension(request, "target_host") or _extract_target_host(
        context
    )


def _request_body_bytes(request: external_auth_pb2.CheckRequest) -> bytes:
    """Read the buffered request body Envoy attaches under with_request_body.

    Envoy uses ``raw_body`` when ``pack_as_bytes`` is true (signing pass)
    and ``body`` otherwise; check both for compatibility.
    """
    try:
        raw = request.attributes.request.http.raw_body
        if raw:
            return raw
        body = request.attributes.request.http.body
        if isinstance(body, str):
            return body.encode("latin-1")
        return body or b""
    except Exception:
        return b""


def _content_digest(body: bytes) -> str:
    """Compute the RFC 9530 Content-Digest header value: ``sha-256=:<b64>:``."""
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def _signable_request_from_check(
    request: external_auth_pb2.CheckRequest,
    headers: dict[str, str],
    content_digest: str,
    target_host: Optional[str],
) -> SignableRequest:
    """Construct the SignableRequest from the ext_authz CheckRequest.

    Uses the trusted ``target_host`` from gRPC initial_metadata so a
    forged Host header cannot redirect the signature.
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
    """Cast an int HTTP code into the proto HttpStatus enum."""
    code_to_enum = {
        200: http_status_pb2.OK,
        400: http_status_pb2.BadRequest,
        401: http_status_pb2.Unauthorized,
        403: http_status_pb2.Forbidden,
        404: http_status_pb2.NotFound,
        500: http_status_pb2.InternalServerError,
        503: http_status_pb2.ServiceUnavailable,
        504: http_status_pb2.GatewayTimeout,
    }
    enum_value = code_to_enum.get(code, http_status_pb2.InternalServerError)
    return http_status_pb2.HttpStatus(code=enum_value)
