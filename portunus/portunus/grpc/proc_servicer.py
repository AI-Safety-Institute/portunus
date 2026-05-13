"""Envoy ``ext_proc`` v3 ``Process`` service.

Handles a bidirectional stream of :class:`ProcessingRequest` /
:class:`ProcessingResponse` per HTTP request (or, in upgraded mode, per
WebSocket connection). Responsibilities:

- Distinguish HTTP vs WebSocket-upgraded streams via Envoy's
  per-route ``filter_metadata`` (set in ``envoy.yaml`` on the routes
  that handle upgrades).

- For HTTP body chunks: submit each chunk to the
  :class:`BoundedPublishQueue` for asynchronous Kinesis publication.

- For WebSocket: feed body bytes through :class:`FrameObserver` to
  surface logical frames (text / binary / ping / pong / close) and
  publish per-frame summary records.

- For headers and trailers: submit via the queue's blocking path so the
  audit trail isn't shaped by drops on the low-volume side.

- Always respond with the empty ``BodyMutation.streamed_response``
  shape required by Envoy 1.36 in ``FULL_DUPLEX_STREAMED`` mode.

- Track active streams so the drain handler can inject WebSocket
  close-code 1012 (Service Restart) on SIGTERM, decoupling task
  lifetime from customer connection lifetime.

Failure-mode contract: the filter side runs with
``failure_mode_allow: true`` — if this server is unreachable or this
servicer errors, Envoy keeps the customer connection alive without
observability. The audit trail loses some bytes, but the customer
sees no disruption.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Optional

import grpc
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as proc_grpc

from portunus.config import config
from portunus.grpc.frame_observer import (
    Direction,
    FrameObserver,
    ObservedFrame,
    build_observer,
)
from portunus.grpc.proxy_auth import extract_proxy_key, is_valid_proxy_key
from portunus.grpc.publish_queue import BoundedPublishQueue, PublishTask
from portunus.models import WSSummaryRecord
from portunus.services.publish_service import PublishService
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")


class StreamMode(Enum):
    """How a given stream should be observed."""

    HTTP = "http"
    WS_UPGRADE = "ws_upgrade"


@dataclass
class _StreamState:
    """Per-stream state held for the lifetime of one ext_proc stream."""

    # Internal stream id, mints with uuid4(); used as the self._active
    # dict key so x-request-id collisions don't drop streams from the
    # drain registry. Distinct from ``request_id`` which is the
    # operator-visible correlation field.
    stream_id: str
    request_id: str
    mode: StreamMode
    observer: Optional[FrameObserver] = None
    upstream_extensions: Optional[str] = None
    drain_requested: asyncio.Event = field(default_factory=asyncio.Event)
    # Wall-clock and monotonic start for the summary record.
    started_at_iso: str = ""
    started_at_monotonic: float = 0.0
    # Per-direction frame counters, keyed by opcode ("text", "binary",
    # "ping", "pong", "close"). Populated only for WS streams.
    client_frame_counts: dict[str, int] = field(default_factory=dict)
    server_frame_counts: dict[str, int] = field(default_factory=dict)
    # First close frame observed wins — populated by _submit_frame.
    close_code: Optional[int] = None
    close_initiator: Optional[str] = None
    # Monotonic body-chunk counters per direction. ext_proc delivers
    # bodies as a stream of chunks; we emit one Kinesis record per
    # chunk with a sequential ``chunk_id`` so the akp Glue ETL
    # (``infra/pipelines/process_raw_data.py:reassemble_body_chunks``)
    # can groupBy(request_id) and concat body bytes ordered by
    # chunk_id at aggregation time. The joined-log schema consumed
    # by aisitok is unchanged — Glue still emits one body record per
    # request_id after reassembly.
    request_chunk_id: int = 0
    response_chunk_id: int = 0


# ext_proc routes Envoy attaches filter_metadata to indicate WS upgrade.
# Envoy config sets:
#   typed_per_filter_config:
#     envoy.filters.http.ext_proc:
#       "@type": ...FilterConfig
#       config: { ... }  with metadata flagging "websocket": true
# This servicer reads that flag from the first ProcessingRequest's
# metadata_context.
_METADATA_NS = "envoy.filters.http.ext_proc"
_WS_METADATA_KEY = "websocket"


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
        # Active streams indexed by an internal stream id (uuid4) so the
        # drain handler can iterate and inject close frames. Keying by
        # x-request-id would collide whenever the client supplies a
        # repeated value (Envoy preserves the header in some trust
        # configs), letting two concurrent streams share a dict slot —
        # drain_all() would then only signal one of them.
        self._active: dict[str, _StreamState] = {}

    @property
    def active_stream_count(self) -> int:
        return len(self._active)

    async def drain_all(self) -> None:
        """Signal every active stream to inject a WS close-code 1012.

        Idempotent — calling twice is a no-op. The streams themselves
        observe the signal on their next ProcessingResponse turn.
        """
        for state in list(self._active.values()):
            state.drain_requested.set()

    async def Process(  # noqa: N802 — proto-defined method name
        self,
        request_iterator: AsyncIterator[proc_pb2.ProcessingRequest],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[proc_pb2.ProcessingResponse]:
        """Handle one ext_proc stream from start to end."""
        # Identity check at stream open. ext_proc streams are long-lived,
        # so this fires once per stream rather than per ProcessingRequest.
        received_proxy_key = extract_proxy_key(context)
        if not is_valid_proxy_key(received_proxy_key, config.grpc.proxy_api_key):
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "Missing or invalid proxy identity",
            )
            return

        state: Optional[_StreamState] = None
        try:
            async for request in request_iterator:
                if state is None:
                    state = self._initialise_stream(request)
                    self._active[state.stream_id] = state

                # If a drain has been requested mid-stream, inject the
                # close frame on the next response turn for WS streams
                # and let Envoy close the connection. HTTP streams are
                # short-lived so we just let them finish.
                if (
                    state.drain_requested.is_set()
                    and state.mode == StreamMode.WS_UPGRADE
                ):
                    yield _inject_ws_close(code=1012, reason="Service restart")
                    return

                async for response in self._dispatch(state, request):
                    yield response
        finally:
            if state is not None:
                self._active.pop(state.stream_id, None)
                if state.mode == StreamMode.WS_UPGRADE:
                    await self._emit_ws_summary(state)

    # ------------------------------------------------------------------
    # Stream setup
    # ------------------------------------------------------------------

    def _initialise_stream(self, first: proc_pb2.ProcessingRequest) -> _StreamState:
        """Inspect the first ProcessingRequest and build per-stream state."""
        request_id = _extract_request_id(first)
        mode = _extract_mode(first)
        observer = (
            build_observer(response_extensions_header=None)
            if mode == StreamMode.WS_UPGRADE
            else None
        )
        return _StreamState(
            stream_id=str(uuid.uuid4()),
            request_id=request_id,
            mode=mode,
            observer=observer,
            started_at_iso=generate_iso_timestamp(),
            started_at_monotonic=time.monotonic(),
        )

    # ------------------------------------------------------------------
    # Per-message dispatch
    # ------------------------------------------------------------------

    async def _dispatch(
        self,
        state: _StreamState,
        request: proc_pb2.ProcessingRequest,
    ) -> AsyncIterator[proc_pb2.ProcessingResponse]:
        """Route a single ProcessingRequest to the right handler.

        Returns an async iterator because some message types (e.g.
        observed-frame batches) can produce multiple responses; most
        produce exactly one empty BodyMutation acknowledgement.
        """
        timestamp = generate_iso_timestamp()

        if request.HasField("request_headers"):
            await self._on_request_headers(state, request.request_headers, timestamp)
            yield _empty_headers_response(request_side=True)
        elif request.HasField("request_body"):
            self._on_body_chunk(
                state,
                request.request_body,
                direction=Direction.REQUEST,
                timestamp=timestamp,
            )
            yield _passthrough_body_response(
                request_side=True,
                body=request.request_body.body,
                end_of_stream=request.request_body.end_of_stream,
            )
        elif request.HasField("request_trailers"):
            await self._on_request_trailers(state, request.request_trailers, timestamp)
            yield _empty_trailers_response(request_side=True)
        elif request.HasField("response_headers"):
            await self._on_response_headers(state, request.response_headers, timestamp)
            yield _empty_headers_response(request_side=False)
        elif request.HasField("response_body"):
            self._on_body_chunk(
                state,
                request.response_body,
                direction=Direction.RESPONSE,
                timestamp=timestamp,
            )
            yield _passthrough_body_response(
                request_side=False,
                body=request.response_body.body,
                end_of_stream=request.response_body.end_of_stream,
            )
        elif request.HasField("response_trailers"):
            await self._on_response_trailers(
                state, request.response_trailers, timestamp
            )
            yield _empty_trailers_response(request_side=False)
        # else: unknown variant — ignore. Envoy adds new ProcessingRequest
        # cases occasionally and we want forward-compat.

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _on_request_headers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpHeaders,
        timestamp: str,
    ) -> None:
        headers = _headers_to_dict(msg.headers)
        await self._queue.submit_blocking(
            PublishTask(
                coro_fn=lambda: self._publish.publish_request_headers(
                    request_id=state.request_id,
                    headers=headers,
                    timestamp=timestamp,
                ),
                label="request_headers",
            )
        )

    async def _on_request_trailers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpTrailers,
        timestamp: str,
    ) -> None:
        trailers = _headers_to_dict(msg.trailers)
        await self._queue.submit_blocking(
            PublishTask(
                coro_fn=lambda: self._publish.publish_request_trailers(
                    request_id=state.request_id,
                    trailers=trailers,
                    timestamp=timestamp,
                ),
                label="request_trailers",
            )
        )

    async def _on_response_headers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpHeaders,
        timestamp: str,
    ) -> None:
        headers = _headers_to_dict(msg.headers)
        # WS upgrades: read Sec-WebSocket-Extensions from the upstream's
        # 101 response and rebuild the observer with the right per-direction
        # PerMessageDeflate state. wsproto's deflate is per-direction;
        # sharing one extension instance silently corrupts frames.
        if state.mode == StreamMode.WS_UPGRADE:
            ext = headers.get("sec-websocket-extensions")
            state.upstream_extensions = ext
            state.observer = build_observer(response_extensions_header=ext)

        await self._queue.submit_blocking(
            PublishTask(
                coro_fn=lambda: self._publish.publish_response_headers(
                    request_id=state.request_id,
                    headers=headers,
                    timestamp=timestamp,
                ),
                label="response_headers",
            )
        )

    async def _on_response_trailers(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpTrailers,
        timestamp: str,
    ) -> None:
        trailers = _headers_to_dict(msg.trailers)
        await self._queue.submit_blocking(
            PublishTask(
                coro_fn=lambda: self._publish.publish_response_trailers(
                    request_id=state.request_id,
                    trailers=trailers,
                    timestamp=timestamp,
                ),
                label="response_trailers",
            )
        )

    def _on_body_chunk(
        self,
        state: _StreamState,
        msg: proc_pb2.HttpBody,
        direction: Direction,
        timestamp: str,
    ) -> None:
        """Dispatch a body chunk to either the HTTP or WS publish path.

        Both paths submit via the droppable queue method — body volume
        is the part we accept may drop under pressure rather than
        backpressure customer traffic.
        """
        if state.mode == StreamMode.WS_UPGRADE and state.observer is not None:
            for frame in state.observer.observe(direction=direction, chunk=msg.body):
                self._submit_frame(state, frame, timestamp)
        else:
            self._submit_http_body(
                state,
                msg.body,
                direction=direction,
                timestamp=timestamp,
                end_of_stream=msg.end_of_stream,
            )

    def _submit_http_body(
        self,
        state: _StreamState,
        body: bytes,
        *,
        direction: Direction,
        timestamp: str,
        end_of_stream: bool,
    ) -> None:
        """Publish one body chunk per ext_proc message with a monotonic id.

        Each chunk lands as its own Kinesis record with a sequential
        ``chunk_id`` per direction and ``num_chunks=0`` (sentinel:
        total unknown until aggregation). The akp Glue ETL in
        ``infra/pipelines/process_raw_data.py:reassemble_body_chunks``
        groups by ``request_id``, sorts by ``chunk_id``, and
        concatenates body bytes, so the joined-log output consumed by
        aisitok stays at one body record per direction — same schema
        as the legacy Lua-filter path.

        Keeping the aggregation downstream means portunus holds no
        body bytes in memory beyond the in-flight ext_proc chunk, and
        streaming responses (Anthropic / OpenAI SSE) flow to Kinesis
        chunk-by-chunk rather than being held until end_of_stream.

        ``end_of_stream`` is unused in the wire format — Glue derives
        the total count via ``count(*)`` after the groupBy. We keep
        the flag in the signature so the dispatch site can wire it
        through if a future schema change reintroduces an explicit
        end-of-stream marker.
        """
        del end_of_stream
        if direction == Direction.REQUEST:
            chunk_id = state.request_chunk_id
            state.request_chunk_id += 1
            publish_method = self._publish.publish_request_body
        else:
            chunk_id = state.response_chunk_id
            state.response_chunk_id += 1
            publish_method = self._publish.publish_response_body

        self._queue.submit_droppable(
            PublishTask(
                coro_fn=lambda: publish_method(
                    request_id=state.request_id,
                    body_bytes=body,
                    timestamp=timestamp,
                    chunk_id=chunk_id,
                    num_chunks=0,
                ),
                label=f"{direction.value}_body",
            )
        )

    async def _emit_ws_summary(self, state: _StreamState) -> None:
        """Build and submit the per-connection WS summary record.

        Submitted via the blocking queue path: WS summaries are one record
        per connection — low volume, and the connection-level shape
        (durations, close codes) is exactly the slice analytics queries
        will reach for, so we'd rather backpressure than drop.
        """
        duration = max(0.0, time.monotonic() - state.started_at_monotonic)
        record = WSSummaryRecord(
            request_id=state.request_id,
            timestamp=state.started_at_iso,
            published_at=generate_iso_timestamp(),
            duration_seconds=duration,
            close_code=state.close_code,
            close_initiator=state.close_initiator,
            client_text_frames=state.client_frame_counts.get("text", 0),
            client_binary_frames=state.client_frame_counts.get("binary", 0),
            client_ping_frames=state.client_frame_counts.get("ping", 0),
            client_pong_frames=state.client_frame_counts.get("pong", 0),
            client_close_frames=state.client_frame_counts.get("close", 0),
            server_text_frames=state.server_frame_counts.get("text", 0),
            server_binary_frames=state.server_frame_counts.get("binary", 0),
            server_ping_frames=state.server_frame_counts.get("ping", 0),
            server_pong_frames=state.server_frame_counts.get("pong", 0),
            server_close_frames=state.server_frame_counts.get("close", 0),
        )
        await self._queue.submit_blocking(
            PublishTask(
                coro_fn=lambda: self._publish.publish_ws_summary(record=record),
                label="ws_summary",
            )
        )

    def _submit_frame(
        self,
        state: _StreamState,
        frame: ObservedFrame,
        timestamp: str,
    ) -> None:
        """Publish one observed WebSocket frame as a body record.

        Each frame is treated as a self-contained body record so that
        downstream consumers (Glue ETL) can reconstruct frame-level
        attribution without needing a new schema.
        """
        counters = (
            state.client_frame_counts
            if frame.direction == Direction.REQUEST
            else state.server_frame_counts
        )
        counters[frame.opcode] = counters.get(frame.opcode, 0) + 1
        if frame.opcode == "close" and state.close_code is None:
            state.close_code = frame.close_code
            state.close_initiator = (
                "client" if frame.direction == Direction.REQUEST else "server"
            )

        publish_method = (
            self._publish.publish_request_body
            if frame.direction == Direction.REQUEST
            else self._publish.publish_response_body
        )
        self._queue.submit_droppable(
            PublishTask(
                coro_fn=lambda: publish_method(
                    request_id=state.request_id,
                    body_bytes=frame.payload,
                    timestamp=timestamp,
                    chunk_id=0,
                    num_chunks=1,
                ),
                label=f"ws_frame_{frame.direction.value}_{frame.opcode}",
            )
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_request_id(req: proc_pb2.ProcessingRequest) -> str:
    """Read x-request-id from the first headers message, or mint one.

    Envoy sets x-request-id automatically for every routed request;
    that value is what shows up in Envoy access logs, so threading it
    through gives operators a single correlatable ID across Envoy and
    Portunus logs.
    """
    if req.HasField("request_headers"):
        for h in req.request_headers.headers.headers:
            if h.key.lower() == "x-request-id":
                value = _header_value(h)
                if value:
                    return value
    return str(uuid.uuid4())


def _header_value(h) -> str:
    """Read the populated value out of an Envoy HeaderValue.

    Envoy 1.20+ moved canonical storage from the deprecated string
    ``value`` field to ``raw_value`` (bytes). Modern Envoy versions
    populate only ``raw_value`` — reading ``value`` returns ``""``,
    which is how an empty PartitionKey ended up on every Kinesis
    publish call. Prefer ``raw_value``, fall back to ``value`` for
    older runtimes.
    """
    raw = getattr(h, "raw_value", b"") or b""
    if raw:
        return raw.decode("utf-8", errors="replace")
    return h.value or ""


def _extract_mode(req: proc_pb2.ProcessingRequest) -> StreamMode:
    """Detect WS-upgrade vs plain-HTTP from filter_metadata on first message."""
    try:
        metadata = req.metadata_context.filter_metadata.get(_METADATA_NS)
        if metadata is None:
            return StreamMode.HTTP
        ws = metadata.fields.get(_WS_METADATA_KEY)
        if ws is not None and ws.bool_value:
            return StreamMode.WS_UPGRADE
    except Exception:
        pass
    return StreamMode.HTTP


def _headers_to_dict(http_headers: base_pb2.HeaderMap) -> dict[str, str]:
    """Flatten Envoy's HeaderMap into a case-folded dict with base64-encoded values.

    Values are base64-encoded for wire compatibility with the previous
    Lua-filter path. ``RequestHeadersRecord`` / ``ResponseHeadersRecord``
    in ``portunus.models`` (and any joined-log ETL downstream) call
    ``_decode_b64_header`` on these values to populate the convenience
    fields (``path``, ``authority``, ``status``, etc.) that downstream
    provider-detection logic consumes. Sending raw strings here would
    break every header record once it lands in Kinesis.
    """
    import base64

    return {
        h.key.lower(): base64.b64encode(_header_value(h).encode("utf-8")).decode(
            "ascii"
        )
        for h in http_headers.headers
    }


def _empty_headers_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """No-op headers response — wrapper around an empty CommonResponse.

    Envoy expects exactly one ``HeadersResponse`` per direction in
    response to a ``request_headers`` / ``response_headers`` message,
    even when the processor doesn't mutate anything.
    """
    hdr = proc_pb2.HeadersResponse(response=proc_pb2.CommonResponse())
    if request_side:
        return proc_pb2.ProcessingResponse(request_headers=hdr)
    return proc_pb2.ProcessingResponse(response_headers=hdr)


def _passthrough_body_response(
    *, request_side: bool, body: bytes, end_of_stream: bool
) -> proc_pb2.ProcessingResponse:
    """Body response that forwards the incoming chunk untouched.

    Envoy 1.36 in FULL_DUPLEX_STREAMED mode reads ``streamed_response.body``
    as "this is the body to send in place of the original chunk." We're
    observing only — but we still need to populate ``body`` with the
    original bytes (empty ``body`` replaces the chunk with empty bytes;
    a ``CommonResponse(status=CONTINUE)`` without ``body_mutation`` is
    rejected as malformed in FDS mode). The cost is one extra copy of
    each chunk on the gRPC stream, which we accept in exchange for
    Envoy producing a correct response to the client.
    """
    body_response = proc_pb2.BodyResponse(
        response=proc_pb2.CommonResponse(
            body_mutation=proc_pb2.BodyMutation(
                streamed_response=proc_pb2.StreamedBodyResponse(
                    body=body,
                    end_of_stream=end_of_stream,
                )
            )
        )
    )
    if request_side:
        return proc_pb2.ProcessingResponse(request_body=body_response)
    return proc_pb2.ProcessingResponse(response_body=body_response)


def _empty_trailers_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """No-op trailers response — required even with no trailer mutation."""
    tr = proc_pb2.TrailersResponse()
    if request_side:
        return proc_pb2.ProcessingResponse(request_trailers=tr)
    return proc_pb2.ProcessingResponse(response_trailers=tr)


def _inject_ws_close(*, code: int, reason: str) -> proc_pb2.ProcessingResponse:
    """Build a response_body that injects a WS close frame.

    Used by the drain protocol: on SIGTERM, every active WS stream's
    next response turn pushes a close-control frame into the
    response direction, signalling the client to reconnect. Per
    RFC 6455 §5.5.1, a close frame is opcode 0x8 with a 2-byte
    big-endian status code optionally followed by a UTF-8 reason.
    """
    reason_bytes = reason.encode("utf-8")
    payload = code.to_bytes(2, "big") + reason_bytes
    # Control frame: FIN=1, opcode=8, mask=0 (server→client), payload length.
    # wsproto would normally build this but we're talking raw to Envoy here.
    frame = bytes([0x88, len(payload)]) + payload
    return proc_pb2.ProcessingResponse(
        response_body=proc_pb2.BodyResponse(
            response=proc_pb2.CommonResponse(
                body_mutation=proc_pb2.BodyMutation(
                    streamed_response=proc_pb2.StreamedBodyResponse(
                        body=frame,
                        end_of_stream=True,
                    )
                )
            )
        )
    )
