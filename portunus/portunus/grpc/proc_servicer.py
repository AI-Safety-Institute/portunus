"""Envoy ``ext_proc`` v3 Process servicer.

Publishes per-request headers, trailers, and body chunks to Kinesis.

Envoy runs the filter with ``observability_mode: true``, so
``ProcessingResponse`` messages are unnecessary and a stream failure here keeps
the customer connection alive (``failure_mode_allow: true``).
"""

from __future__ import annotations

import base64
import logging
import time
import uuid
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import grpc
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc
from google.protobuf.json_format import MessageToDict

from portunus.config import config
from portunus.grpc.frame_observer import Direction
from portunus.grpc.proxy_auth import extract_proxy_key, is_valid_proxy_key
from portunus.request_context import parse_trace_root, request_id_var, set_trace_id
from portunus.services.publish_queue import BoundedPublishQueue, PublishTask
from portunus.services.publish_service import PublishService
from portunus.util import chunk_body_data, generate_iso_timestamp

logger = logging.getLogger("api.access")


# Namespace ext_authz populates with ``principal_info`` / ``secret_arn``,
# forwarded via ``metadata_options.forwarding_namespaces``.
_AUTH_METADATA_NS = "envoy.filters.http.ext_authz"
_AUTH_PRINCIPAL_INFO_KEY = "principal_info"
_AUTH_SECRET_ARN_KEY = "secret_arn"
_AUTH_UPSTREAM_HEADER_KEY = "upstream_auth_header"


@dataclass(slots=True)
class _StreamState:
    """Per-stream state held for the lifetime of one ext_proc stream."""

    # uuid4 registry key: x-request-id can collide across concurrent streams,
    # which would evict a stream and lose its close-time summary record.
    stream_id: str
    request_id: str
    # Header ext_authz wrote the upstream credential to (from its dynamic
    # metadata); excluded from capture whatever its name.
    upstream_auth_header: Optional[str] = None
    # Audit consumers reassemble each direction by request_id and chunk_id.
    request_chunk_id: int = 0
    response_chunk_id: int = 0
    request_complete: bool = False
    response_complete: bool = False
    audit_metadata_published: bool = False


class PortunusProcessServicer(proc_grpc.ExternalProcessorServicer):
    """Envoy ext_proc v3 ``ExternalProcessorServicer`` implementation."""

    def __init__(
        self,
        *,
        publish_service: PublishService,
        publish_queue: BoundedPublishQueue,
    ) -> None:
        self._publish = publish_service
        self._queue = publish_queue
        self._active: dict[str, _StreamState] = {}
        self._next_drop_warning = 0.0
        self._suppressed_drop_warnings = 0

    @property
    def active_stream_count(self) -> int:
        return len(self._active)

    async def Process(  # noqa: N802 — proto-defined method name
        self,
        request_iterator: AsyncIterator[proc_pb2.ProcessingRequest],
        context: grpc.aio.ServicerContext,
    ) -> None:
        """Handle one stream with the gRPC coroutine read/write API."""
        received_proxy_key = extract_proxy_key(context)
        if not is_valid_proxy_key(received_proxy_key, config.grpc.proxy_api_key):
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "Missing or invalid proxy identity",
            )
            return

        state: Optional[_StreamState] = None
        try:
            while True:
                request = await context.read()
                if request is grpc.aio.EOF:
                    break
                if state is None:
                    state = self._initialise_stream(request)
                    self._active[state.stream_id] = state

                response = await self._dispatch(state, request)
                if response is not None:
                    await context.write(response)

                kind = request.WhichOneof("request")
                if kind is not None:
                    message = getattr(request, kind)
                    ended = kind.endswith("_trailers") or getattr(
                        message, "end_of_stream", False
                    )
                    if ended and kind.startswith("request_"):
                        state.request_complete = True
                    elif ended and kind.startswith("response_"):
                        state.response_complete = True
                # Completed HTTP capture need not retain Envoy's deferred-close slot.
                if state.request_complete and state.response_complete:
                    return
        finally:
            if state is not None:
                self._active.pop(state.stream_id, None)

    def _initialise_stream(self, first: proc_pb2.ProcessingRequest) -> _StreamState:
        """Inspect the first ProcessingRequest and build per-stream state.

        Also binds the correlation contextvars: each ext_proc stream is one
        grpc.aio task, so setting them here covers every log line the stream
        emits.
        """
        request_id = _extract_request_id(first)
        request_id_var.set(request_id)
        trace_root = parse_trace_root(_extract_header(first, "x-amzn-trace-id"))
        if trace_root:
            set_trace_id(trace_root)
        try:
            meta_keys = list(first.metadata_context.filter_metadata.keys())
        except Exception:
            meta_keys = []
        logger.debug(
            "STREAM_INIT request_id=%s metadata_ns_keys=%s",
            request_id,
            meta_keys,
        )
        return _StreamState(stream_id=str(uuid.uuid4()), request_id=request_id)

    async def _dispatch(
        self,
        state: _StreamState,
        request: proc_pb2.ProcessingRequest,
    ) -> Optional[proc_pb2.ProcessingResponse]:
        """Capture a message and reply only when the protocol needs it."""
        timestamp = generate_iso_timestamp()

        if request.HasField("request_headers"):
            await self._on_request_headers(state, request, timestamp)
            if request.request_headers.end_of_stream:
                await self._finish_http_body(state, Direction.REQUEST, timestamp)
            if not request.observability_mode:
                return _empty_headers_response(request_side=True)
        elif request.HasField("request_body"):
            await self._on_body_chunk(
                state,
                request.request_body,
                direction=Direction.REQUEST,
                timestamp=timestamp,
            )
            if not request.observability_mode:
                return _empty_body_response(request_side=True)
        elif request.HasField("request_trailers"):
            await self._on_request_trailers(state, request.request_trailers, timestamp)
            await self._finish_http_body(state, Direction.REQUEST, timestamp)
            if not request.observability_mode:
                return _empty_trailers_response(request_side=True)
        elif request.HasField("response_headers"):
            await self._on_response_headers(state, request.response_headers, timestamp)
            if request.response_headers.end_of_stream:
                await self._finish_http_body(state, Direction.RESPONSE, timestamp)
            if not request.observability_mode:
                return _empty_headers_response(request_side=False)
        elif request.HasField("response_body"):
            await self._on_body_chunk(
                state,
                request.response_body,
                direction=Direction.RESPONSE,
                timestamp=timestamp,
            )
            if not request.observability_mode:
                return _empty_body_response(request_side=False)
        elif request.HasField("response_trailers"):
            await self._on_response_trailers(
                state, request.response_trailers, timestamp
            )
            await self._finish_http_body(state, Direction.RESPONSE, timestamp)
            if not request.observability_mode:
                return _empty_trailers_response(request_side=False)
        # Unknown variants are silently ignored for forward-compat.
        return None

    async def _on_request_headers(
        self,
        state: _StreamState,
        request: proc_pb2.ProcessingRequest,
        timestamp: str,
    ) -> None:
        # One audit metadata record per stream from forwarded ext_authz
        # dynamic_metadata; missing namespace means ext_authz was disabled on
        # this route (e.g. /ping).
        if not state.audit_metadata_published:
            principal_info, secret_arn, state.upstream_auth_header = (
                _extract_auth_metadata(request)
            )
            if principal_info is not None:
                await self._queue.submit_blocking(
                    PublishTask(
                        build=lambda: self._publish.build_metadata(
                            request_id=state.request_id,
                            timestamp=timestamp,
                            principal_info=principal_info,
                            secret_arn=secret_arn,
                        ),
                        label="metadata",
                        request_id=state.request_id,
                    ),
                    timeout=config.grpc.publish_blocking_timeout_seconds,
                )
            state.audit_metadata_published = True

        headers = _headers_to_dict(
            request.request_headers.headers, also_redact=state.upstream_auth_header
        )
        await self._queue.submit_blocking(
            PublishTask(
                build=lambda: self._publish.build_request_headers(
                    request_id=state.request_id,
                    headers=headers,
                    timestamp=timestamp,
                ),
                label="request_headers",
                request_id=state.request_id,
            ),
            timeout=config.grpc.publish_blocking_timeout_seconds,
        )

    async def _on_request_trailers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpTrailers,
        timestamp: str,
    ) -> None:
        trailers = _headers_to_dict(
            msg.trailers, also_redact=state.upstream_auth_header
        )
        await self._queue.submit_blocking(
            PublishTask(
                build=lambda: self._publish.build_request_trailers(
                    request_id=state.request_id,
                    trailers=trailers,
                    timestamp=timestamp,
                ),
                label="request_trailers",
                request_id=state.request_id,
            ),
            timeout=config.grpc.publish_blocking_timeout_seconds,
        )

    async def _on_response_headers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpHeaders,
        timestamp: str,
    ) -> None:
        headers = _headers_to_dict(msg.headers, also_redact=state.upstream_auth_header)
        await self._queue.submit_blocking(
            PublishTask(
                build=lambda: self._publish.build_response_headers(
                    request_id=state.request_id,
                    headers=headers,
                    timestamp=timestamp,
                ),
                label="response_headers",
                request_id=state.request_id,
            ),
            timeout=config.grpc.publish_blocking_timeout_seconds,
        )

    async def _on_response_trailers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpTrailers,
        timestamp: str,
    ) -> None:
        trailers = _headers_to_dict(
            msg.trailers, also_redact=state.upstream_auth_header
        )
        await self._queue.submit_blocking(
            PublishTask(
                build=lambda: self._publish.build_response_trailers(
                    request_id=state.request_id,
                    trailers=trailers,
                    timestamp=timestamp,
                ),
                label="response_trailers",
                request_id=state.request_id,
            ),
            timeout=config.grpc.publish_blocking_timeout_seconds,
        )

    async def _finish_http_body(
        self, state: _StreamState, direction: Direction, timestamp: str
    ) -> None:
        await self._on_body_chunk(
            state,
            proc_pb2.HttpBody(end_of_stream=True),
            direction,
            timestamp,
        )

    async def _on_body_chunk(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpBody,
        direction: Direction,
        timestamp: str,
    ) -> None:
        """Publish one HttpBody as ordered, record-sized body records."""
        # One HttpBody may split into several record-sized pieces; only the
        # last record of an ``end_of_stream`` message is the body's terminal
        # chunk. Marking it gives the ETL an explicit end-of-body signal the
        # ``num_chunks=0`` wire format lacks (a lost trailing chunk would
        # otherwise leave contiguous chunk_ids indistinguishable from a
        # complete body).
        body_chunks = chunk_body_data(msg.body) or [b""]
        last_index = len(body_chunks) - 1
        for index, body_chunk in enumerate(body_chunks):
            chunk_id = self._next_chunk_id(state, direction)
            await self._submit_body_record(
                state=state,
                direction=direction,
                body_bytes=body_chunk,
                timestamp=timestamp,
                chunk_id=chunk_id,
                label=f"{direction.value}_body",
                final_chunk=msg.end_of_stream and index == last_index,
            )

    def _next_chunk_id(self, state: _StreamState, direction: Direction) -> int:
        """Allocate the next body record chunk_id for one direction."""
        if direction == Direction.REQUEST:
            chunk_id = state.request_chunk_id
            state.request_chunk_id += 1
            return chunk_id
        chunk_id = state.response_chunk_id
        state.response_chunk_id += 1
        return chunk_id

    async def _submit_body_record(
        self,
        *,
        state: _StreamState,
        direction: Direction,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        label: str,
        final_chunk: bool = False,
    ) -> bool:
        """Submit one record-sized body chunk.

        ``final_chunk`` marks a streamed HTTP body's terminal chunk (the one
        carrying Envoy's ``end_of_stream``) so the Glue ETL can detect a lost
        trailing chunk in the ``num_chunks=0`` wire format.
        """
        build_method = (
            self._publish.build_request_body
            if direction == Direction.REQUEST
            else self._publish.build_response_body
        )
        accepted = self._queue.submit_droppable(
            PublishTask(
                build=lambda body_bytes=body_bytes, chunk_id=chunk_id: build_method(  # type: ignore[misc]
                    request_id=state.request_id,
                    body_bytes=body_bytes,
                    timestamp=timestamp,
                    chunk_id=chunk_id,
                    num_chunks=0,
                    final_chunk=final_chunk,
                ),
                label=label,
                request_id=state.request_id,
                # Closure retains the raw chunk until flush — charge it against
                # the queue's byte budget.
                size_bytes=len(body_bytes),
            )
        )
        if not accepted:
            now = time.monotonic()
            if now >= self._next_drop_warning:
                logger.warning(
                    "Body chunk dropped under queue pressure on stream %s "
                    "(%s direction, chunk_id=%d, bytes=%d); "
                    "%d additional warnings suppressed; exact losses in metrics",
                    state.stream_id,
                    direction.value,
                    chunk_id,
                    len(body_bytes),
                    self._suppressed_drop_warnings,
                )
                self._next_drop_warning = now + 1.0
                self._suppressed_drop_warnings = 0
            else:
                self._suppressed_drop_warnings += 1
        return accepted


def _extract_request_id(req: proc_pb2.ProcessingRequest) -> str:
    """Read x-request-id from the first headers message, or mint one."""
    value = _extract_header(req, "x-request-id")
    if value:
        return value
    return str(uuid.uuid4())


def _extract_header(req: proc_pb2.ProcessingRequest, name: str) -> str:
    """Read a request header from a headers message; "" if absent."""
    if req.HasField("request_headers"):
        for h in req.request_headers.headers.headers:
            if h.key.lower() == name:
                value = _header_value(h)
                if value:
                    return value
    return ""


def _header_value_bytes(h) -> bytes:
    """Read the populated value out of an Envoy HeaderValue as raw bytes.

    ``raw_value`` wins when both are set. Divergence is logged with byte counts
    only, since header content could leak credentials.
    """
    raw = getattr(h, "raw_value", b"") or b""
    legacy = (h.value or "").encode("utf-8")
    if raw and legacy and raw != legacy:
        logger.warning(
            "HeaderValue field divergence on %r: raw_len=%d legacy_len=%d",
            h.key,
            len(raw),
            len(legacy),
        )
    return raw or legacy


def _extract_auth_metadata(
    req: proc_pb2.ProcessingRequest,
) -> tuple[Optional[dict], Optional[str], Optional[str]]:
    """Pull the audit identity and credential header from ext_authz metadata.

    That is ``principal_info``, ``secret_arn`` and ``upstream_auth_header``.

    Returns ``(None, None, None)`` when ext_authz is disabled on the route
    (e.g. /ping).
    """
    try:
        ns = req.metadata_context.filter_metadata.get(_AUTH_METADATA_NS)
    except Exception:
        return None, None, None
    if ns is None:
        return None, None, None

    principal_info: Optional[dict] = None
    pi_value = ns.fields.get(_AUTH_PRINCIPAL_INFO_KEY)
    if pi_value is not None and pi_value.HasField("struct_value"):
        principal_info = MessageToDict(pi_value.struct_value)

    secret_arn: Optional[str] = None
    sa_value = ns.fields.get(_AUTH_SECRET_ARN_KEY)
    if sa_value is not None and sa_value.HasField("string_value"):
        secret_arn = sa_value.string_value

    upstream_auth_header: Optional[str] = None
    uh_value = ns.fields.get(_AUTH_UPSTREAM_HEADER_KEY)
    if uh_value is not None and uh_value.HasField("string_value"):
        upstream_auth_header = uh_value.string_value.lower()

    return principal_info, secret_arn, upstream_auth_header


def _header_value(h) -> str:
    """Return ``_header_value_bytes`` decoded as UTF-8 with replacement."""
    return _header_value_bytes(h).decode("utf-8", errors="replace")


def _excluded_header_names(also_redact: Optional[str]) -> frozenset[str]:
    """Header names (lower-cased) left out of ``raw_headers``.

    The configured credential headers (``KNOWN_AUTH_HEADERS``), the
    ``api_key_header`` the client's payload arrives in and, per stream, the
    header ext_authz wrote the upstream credential to (``also_redact``), so a
    secret's own ``output_header`` such as ``xi-api-key`` is never archived.
    """
    names = set(config.known_auth_headers)
    names.add(config.api_key_header.lower())
    if also_redact:
        names.add(also_redact.lower())
    return frozenset(names)


def _headers_to_dict(
    http_headers: base_pb2.HeaderMap, *, also_redact: Optional[str] = None
) -> dict[str, str]:
    """Flatten Envoy's HeaderMap into a case-folded dict of base64 values.

    Captures every header except the credential headers named by
    :func:`_excluded_header_names`. ext_proc observes headers after ext_authz
    substitutes the real key, so publishing those verbatim would archive
    customer secrets; everything else, custom ``x-aisi-*`` headers included,
    is recorded.

    Base64 operates on raw bytes so non-UTF-8 values survive losslessly; Glue
    ETL calls ``_decode_b64_header`` on them.
    """
    excluded = _excluded_header_names(also_redact)
    result: dict[str, str] = {}
    for header in http_headers.headers:
        name = header.key.lower()
        if name in excluded:
            continue
        result[name] = base64.b64encode(_header_value_bytes(header)).decode("ascii")
    return result


def _empty_headers_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """No-op headers response — required even when not mutating."""
    hdr = proc_pb2.HeadersResponse(response=proc_pb2.CommonResponse())
    if request_side:
        return proc_pb2.ProcessingResponse(request_headers=hdr)
    return proc_pb2.ProcessingResponse(response_headers=hdr)


def _empty_body_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """Acknowledge a body chunk without altering it in blocking mode."""
    body = proc_pb2.BodyResponse(response=proc_pb2.CommonResponse())
    if request_side:
        return proc_pb2.ProcessingResponse(request_body=body)
    return proc_pb2.ProcessingResponse(response_body=body)


def _empty_trailers_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """No-op trailers response — required even when not mutating."""
    tr = proc_pb2.TrailersResponse()
    if request_side:
        return proc_pb2.ProcessingResponse(request_trailers=tr)
    return proc_pb2.ProcessingResponse(response_trailers=tr)
