"""Envoy ``ext_authz`` v3 Check servicer.

A single header-only pass: authenticates the bearer and returns the upstream
credential as a header mutation. The request body is never sent to this
servicer. A bearer is either a payload (the caller's AWS credentials plus a
secret ARN) or, when configured, an on-behalf-of access token minted by the
auth relay (``services/jwt_auth_service.py``).

Audit metadata is published from the ext_proc pass via
``CheckResponse.dynamic_metadata``, keeping Kinesis writes off the
auth-latency critical path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

import grpc
from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import status_pb2

from portunus.config import config
from portunus.exceptions import (
    AuthenticationError,
    AuthOverloadedError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
    UpstreamServiceError,
)
from portunus.grpc.proxy_auth import (
    extract_proxy_key,
    is_valid_proxy_key,
)
from portunus.grpc.proxy_auth import (
    extract_target_host as _extract_target_host,
)
from portunus.metrics import (
    CHECK_ALLOWED,
    CHECK_DENIED,
    CHECK_ERROR,
    CHECK_LATENCY,
    CHECK_SHED,
    metrics,
)
from portunus.models import AuthPayload, AuthResult
from portunus.request_context import parse_trace_root, request_id_var, set_trace_id
from portunus.services.auth_service import AuthService
from portunus.services.jwt_auth_service import JwtAuthService, looks_like_jwt

logger = logging.getLogger("api.access")


# Below Envoy's 10 s ext_authz deadline so a stalled STS / Secrets Manager
# call or mint surfaces as a structured 504 from Portunus. A cold mint needs
# the STS identity call, the secret fetch, then up to MINT_DEADLINE_SECONDS.
_AUTH_TIMEOUT_S = 9.0
# Answered by Check itself (a 200 ``denied_response`` Envoy sends straight
# to the client), so the proxy can tell a signed-in app which models its
# user may use here without a second listener. Never forwarded upstream.
ENTITLEMENTS_PATH = "/.well-known/portunus/entitlements"


class PortunusAuthServicer(external_auth_pb2_grpc.AuthorizationServicer):
    """Envoy ext_authz v3 ``AuthorizationServicer`` implementation."""

    def __init__(
        self,
        *,
        auth_service: AuthService,
        jwt_auth_service: Optional[JwtAuthService] = None,
    ) -> None:
        self._auth = auth_service
        self._jwt_auth = jwt_auth_service

    async def Check(  # noqa: N802 — proto-defined method name
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> external_auth_pb2.CheckResponse:
        """Handle an Envoy ext_authz Check call.

        Never raises — failures are reported as ``denied_response``. This is the
        one place Check outcomes and latency are metered.
        """
        started = time.perf_counter()
        response = await self._check_inner(request, context)
        metrics.observe(CHECK_LATENCY, (time.perf_counter() - started) * 1000)
        if response.HasField("denied_response"):
            metrics.incr(CHECK_DENIED)
            status = response.denied_response.status.code
            if status == 503:
                metrics.incr(CHECK_SHED)
            elif status >= 500:
                metrics.incr(CHECK_ERROR)
        else:
            metrics.incr(CHECK_ALLOWED)
        return response

    async def _check_inner(
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> external_auth_pb2.CheckResponse:
        request_id = self._extract_request_id(request)
        # Task-local under grpc.aio: every log line in this RPC carries the id.
        request_id_var.set(request_id)

        received_proxy_key = extract_proxy_key(context)
        if not is_valid_proxy_key(received_proxy_key, config.grpc.proxy_api_key):
            return _denied(
                code=401,
                body="Missing or invalid proxy identity",
                request_id=request_id,
            )

        headers = _http_headers(request)
        # Authenticated Envoy metadata is preferred over the HTTP header: a
        # client can forge the latter, and only the former is Envoy's own.
        trace_header = headers.get("x-amzn-trace-id", "")
        for key, value in context.invocation_metadata() or ():
            if key == "x-amzn-trace-id" and isinstance(value, str):
                trace_header = value
                break
        trace_root = parse_trace_root(trace_header)
        if trace_root:
            # Correlation only — surface the upstream trace id on every log
            # line of this RPC.
            set_trace_id(trace_root)
        return await self._authenticate(request, context, request_id, headers)

    async def _authenticate(
        self,
        request: external_auth_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
        request_id: str,
        headers: dict[str, str],
    ) -> external_auth_pb2.CheckResponse:
        """Authenticate the bearer payload carried in the request headers."""
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

            # target_host comes from Envoy-controlled route context / gRPC
            # initial_metadata, never client-controllable headers.
            target_host = _extract_target_host_for_check(request, context)

            path = request.attributes.request.http.path.split("?", 1)[0]
            if path == ENTITLEMENTS_PATH:
                if self._jwt_auth is None or not looks_like_jwt(raw_payload):
                    return _denied(
                        code=401,
                        body="Entitlements need a Portunus access token",
                        request_id=request_id,
                    )
                async with asyncio.timeout(_AUTH_TIMEOUT_S):
                    body = await self._jwt_auth.entitlements(
                        raw_payload, request_id, target_host
                    )
                return _direct_json(200, body)

            if self._jwt_auth is not None and looks_like_jwt(raw_payload):
                try:
                    async with asyncio.timeout(_AUTH_TIMEOUT_S):
                        auth_result, jwt_secret_arn = await self._jwt_auth.authenticate(
                            raw_payload,
                            request_id,
                            target_host,
                            request_body=_request_body(request),
                        )
                except TimeoutError:
                    return _denied(
                        code=504, body="Auth backend timeout", request_id=request_id
                    )
                return _ok(
                    auth_result=auth_result,
                    principal_info=auth_result.principal_info.to_dict(),
                    secret_arn=jwt_secret_arn,
                )

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

            return _ok(
                auth_result=auth_result,
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
        except UpstreamServiceError as e:
            # A dependency needed to mint the credential is down; the message
            # is curated to carry no endpoint detail.
            return _denied(code=503, body=e.message, request_id=request_id)
        except AuthOverloadedError as e:
            return _denied(code=503, body=e.message, request_id=request_id)
        except Exception as e:
            # Log type name only — boto / pydantic / wsproto messages can carry
            # payload bytes.
            logger.error(
                "Unhandled error in Check (request_id=%s): %s",
                request_id,
                type(e).__name__,
            )
            return _denied(
                code=500, body="Internal server error", request_id=request_id
            )

    @staticmethod
    def _extract_request_id(request: external_auth_pb2.CheckRequest) -> str:
        """Pull Envoy's ``x-request-id`` from the Check request, or mint one.

        The header is the id Envoy's access log and the ext_proc audit
        records carry, so it is the only key that joins this RPC's log lines
        to them. ``attributes.request.http.id`` is Envoy's numeric stream id,
        which appears nowhere else; it is the fallback when the header is
        missing.
        """
        try:
            return (
                _http_headers(request).get("x-request-id")
                or request.attributes.request.http.id
                or str(uuid.uuid4())
            )
        except Exception:
            return str(uuid.uuid4())


def upstream_auth_header(auth_result: AuthResult) -> tuple[str, str]:
    """Resolve the upstream header that carries the credential, and its value.

    ``output_header`` / ``output_prefix`` come from the secret (or are fixed for
    minted tokens). A missing or empty ``output_header`` falls back to the
    configured ``api_key_header``; a missing ``output_prefix`` falls back to the
    configured prefix, while an empty one means no prefix.

    Returns:
        The lower-cased header name and the full header value.
    """
    header = auth_result.output_header or config.api_key_header
    prefix = (
        auth_result.output_prefix
        if auth_result.output_prefix is not None
        else config.api_key_prefix
    )
    return header.lower(), f"{prefix}{auth_result.api_key}"


def _ok(
    *,
    auth_result: AuthResult,
    principal_info: Optional[Dict[str, Any]] = None,
    secret_arn: Optional[str] = None,
) -> external_auth_pb2.CheckResponse:
    """Build a CheckResponse that allows the request with header mutations.

    Sets the upstream credential header and removes the header the payload
    arrived in when the two differ; every other header is forwarded as-is.
    The upstream header name goes into dynamic metadata so the audit path can
    redact it even when it is not a well-known credential header.

    An empty ``api_key`` means there is no credential to inject (Envoy signs
    the upstream request itself): only the inbound header is removed.
    """
    response = external_auth_pb2.CheckResponse()
    response.status.code = 0
    ok = response.ok_response
    ok.SetInParent()

    inbound_header = config.api_key_header.lower()
    if auth_result.api_key == "":
        ok.headers_to_remove.append(inbound_header)
        header = inbound_header
    else:
        header, value = upstream_auth_header(auth_result)
        added = ok.headers.add()
        added.header.key = header
        added.header.value = value
        added.append_action = base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD
        if header != inbound_header:
            ok.headers_to_remove.append(inbound_header)

    response.dynamic_metadata.update({"upstream_auth_header": header})
    if principal_info is not None:
        response.dynamic_metadata.update({"principal_info": principal_info})
    if secret_arn is not None:
        response.dynamic_metadata.update({"secret_arn": secret_arn})
    return response


def _direct_json(code: int, body: Dict[str, Any]) -> external_auth_pb2.CheckResponse:
    """A response Envoy returns to the client itself, instead of proxying.

    ext_authz sends ``denied_response`` verbatim whenever ``status`` is not
    OK, whatever HTTP status it carries, so this doubles as a direct reply.
    """
    return external_auth_pb2.CheckResponse(
        status=status_pb2.Status(
            code=grpc.StatusCode.PERMISSION_DENIED.value[0], message="direct"
        ),
        denied_response=external_auth_pb2.DeniedHttpResponse(
            status=_http_status(code),
            body=json.dumps(body, separators=(",", ":")),
            headers=[
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(
                        key="content-type", value="application/json"
                    ),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
                ),
                base_pb2.HeaderValueOption(
                    header=base_pb2.HeaderValue(key="cache-control", value="no-store"),
                    append_action=base_pb2.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
                ),
            ],
        ),
    )


def _denied(
    *,
    code: int,
    body: str,
    request_id: str,
) -> external_auth_pb2.CheckResponse:
    """Build a CheckResponse denying the request with a specific HTTP code.

    Body shape ``{"error": {"message": ..., "request_id": ...}}`` is a stable
    client contract — do not change.
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


def _request_body(request: external_auth_pb2.CheckRequest) -> Optional[bytes]:
    """The buffered request body, when Envoy was configured to send one."""
    http = request.attributes.request.http
    if http.raw_body:
        return bytes(http.raw_body)
    if http.body:
        return http.body.encode()
    return None


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
