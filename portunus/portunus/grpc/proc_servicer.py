"""Envoy ``ext_proc`` v3 Process servicer.

Handles a bidirectional stream of ``ProcessingRequest`` /
``ProcessingResponse`` per HTTP request: publishes headers, trailers,
and body chunks to Firehose; for upgraded WebSocket streams, post-101
bytes are parsed through :class:`FrameObserver` into per-frame records
plus a ``WSSummaryRecord`` at stream end.

Envoy runs the filter with ``observability_mode: true``, so yielded
``ProcessingResponse`` messages are ignored and a stream failure here
keeps the customer connection alive (``failure_mode_allow: true``).
"""

from __future__ import annotations

import base64
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
from google.protobuf.json_format import MessageToDict

from portunus.config import config
from portunus.grpc.frame_observer import (
    Direction,
    FrameObserver,
    ObservedFrame,
    build_observer,
)
from portunus.grpc.proxy_auth import extract_proxy_key, is_valid_proxy_key
from portunus.models import WSSummaryRecord
from portunus.services.publish_queue import BoundedPublishQueue, PublishTask
from portunus.services.publish_service import PublishService
from portunus.util import chunk_body_data, generate_iso_timestamp

logger = logging.getLogger("api.access")


# Hard cap on pre-101 buffered bytes per stream — realistic handshakes
# complete in <10 KB.
_PRE_101_MAX_BYTES = 256 * 1024

_METADATA_NS = "envoy.filters.http.ext_proc"
_WS_METADATA_KEY = "websocket"

# Namespace ext_authz #1 populates with ``principal_info`` / ``secret_arn``;
# Envoy forwards it via ``metadata_options.forwarding_namespaces``.
_AUTH_METADATA_NS = "envoy.filters.http.ext_authz"
_AUTH_PRINCIPAL_INFO_KEY = "principal_info"
_AUTH_SECRET_ARN_KEY = "secret_arn"


class StreamMode(Enum):
    """How a given stream should be observed."""

    HTTP = "http"
    WS_UPGRADE = "ws_upgrade"


@dataclass
class _StreamState:
    """Per-stream state held for the lifetime of one ext_proc stream."""

    # uuid4 — keyed in self._active so x-request-id collisions between
    # concurrent streams don't evict each other from the active registry
    # (which would lose the summary record at close).
    stream_id: str
    request_id: str
    mode: StreamMode = StreamMode.HTTP
    observer: Optional[FrameObserver] = None
    upstream_extensions: Optional[str] = None
    started_at_iso: str = ""
    started_at_monotonic: float = 0.0
    # Per-direction sequential chunk ids — Glue
    # (``infra/pipelines/process_raw_data.py:reassemble_body_chunks``)
    # groups by request_id and concatenates body bytes ordered by chunk_id.
    request_chunk_id: int = 0
    response_chunk_id: int = 0
    # Per-direction WS frame ordinal. chunk_id is monotonic across the whole
    # direction (a single frame may span several body-record chunks), so it
    # can't identify a frame; frame_index does. Downstream Glue keys WS frames
    # by (request_id, frame_index) to reassemble per-frame and to disambiguate
    # otherwise-identical frames (same body + timestamp) that would collide on
    # a body-hash row key. HTTP body records leave frame_index None.
    request_frame_index: int = 0
    response_frame_index: int = 0
    client_frame_counts: dict[str, int] = field(default_factory=dict)
    server_frame_counts: dict[str, int] = field(default_factory=dict)
    # Audit-integrity counters: incremented when a frame is dropped by the
    # publish queue (queue saturated) or arrives marked truncated by the
    # deflate cap. Surfaced via WSSummaryRecord at stream end.
    dropped_client_frames: int = 0
    dropped_server_frames: int = 0
    truncated_client_frames: int = 0
    truncated_server_frames: int = 0
    close_code: Optional[int] = None
    close_initiator: Optional[str] = None
    # WS body bytes that arrived before response_headers (which carries
    # Sec-WebSocket-Extensions). Replayed once the observer is built.
    pre_101_buffer: list[tuple[Direction, bytes]] = field(default_factory=list)
    pre_101_bytes: int = 0
    # Set when the pre-101 buffer cap is hit. Truncating raw WS bytes
    # mid-frame would desync the frame parser + per-direction zlib inflate
    # state, silently corrupting every subsequent frame. Instead we poison
    # the stream: skip frame observation entirely and report the loss via
    # the truncated counters / WSSummaryRecord rather than replaying a
    # corrupt prefix.
    pre_101_poisoned: bool = False
    response_headers_seen: bool = False
    summary_emitted: bool = False
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

    @property
    def active_stream_count(self) -> int:
        return len(self._active)

    async def Process(  # noqa: N802 — proto-defined method name
        self,
        request_iterator: AsyncIterator[proc_pb2.ProcessingRequest],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[proc_pb2.ProcessingResponse]:
        """Handle one ext_proc stream from start to end."""
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

                async for response in self._dispatch(state, request):
                    yield response
        finally:
            if state is not None:
                self._active.pop(state.stream_id, None)
                if state.mode == StreamMode.WS_UPGRADE:
                    await self._emit_ws_summary(state, droppable=False)

    def _initialise_stream(self, first: proc_pb2.ProcessingRequest) -> _StreamState:
        """Inspect the first ProcessingRequest and build per-stream state."""
        request_id = _extract_request_id(first)
        mode = _extract_mode(first)
        try:
            meta_keys = list(first.metadata_context.filter_metadata.keys())
        except Exception:
            meta_keys = []
        logger.debug(
            "STREAM_INIT request_id=%s mode=%s metadata_ns_keys=%s",
            request_id,
            mode.value,
            meta_keys,
        )
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

    async def _dispatch(
        self,
        state: _StreamState,
        request: proc_pb2.ProcessingRequest,
    ) -> AsyncIterator[proc_pb2.ProcessingResponse]:
        """Route a single ProcessingRequest to the right handler."""
        timestamp = generate_iso_timestamp()

        if request.HasField("request_headers"):
            await self._on_request_headers(state, request, timestamp)
            yield _empty_headers_response(request_side=True)
        elif request.HasField("request_body"):
            self._on_body_chunk(
                state,
                request.request_body,
                direction=Direction.REQUEST,
                timestamp=timestamp,
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
        elif request.HasField("response_trailers"):
            await self._on_response_trailers(
                state, request.response_trailers, timestamp
            )
            yield _empty_trailers_response(request_side=False)
        # Unknown variants are silently ignored for forward-compat.

    async def _on_request_headers(
        self,
        state: _StreamState,
        request: proc_pb2.ProcessingRequest,
        timestamp: str,
    ) -> None:
        # Publish one audit metadata record per stream from the
        # forwarded ext_authz dynamic_metadata; missing namespace means
        # ext_authz was disabled on this route (e.g. /ping).
        if not state.audit_metadata_published:
            principal_info, secret_arn = _extract_auth_metadata(request)
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
                    )
                )
            state.audit_metadata_published = True

        headers = _headers_to_dict(request.request_headers.headers)
        await self._queue.submit_blocking(
            PublishTask(
                build=lambda: self._publish.build_request_headers(
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
                build=lambda: self._publish.build_request_trailers(
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
        # For WS upgrades, rebuild the observer with the per-direction
        # PerMessageDeflate state negotiated in the 101 response, then
        # replay buffered pre-101 bytes through it in arrival order.
        if state.mode == StreamMode.WS_UPGRADE:
            ext_b64 = headers.get("sec-websocket-extensions")
            ext: Optional[str] = None
            if ext_b64:
                try:
                    ext = base64.b64decode(ext_b64).decode("utf-8", errors="replace")
                except Exception:
                    ext = None
            state.upstream_extensions = ext
            state.observer = build_observer(response_extensions_header=ext)
            state.response_headers_seen = True
            self._replay_pre_101(state, timestamp)

        await self._queue.submit_blocking(
            PublishTask(
                build=lambda: self._publish.build_response_headers(
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
                build=lambda: self._publish.build_response_trailers(
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
        """Dispatch a body chunk to either the HTTP or WS publish path."""
        if state.mode == StreamMode.WS_UPGRADE:
            # A poisoned stream (pre-101 buffer overflow) has desynced frame
            # state; observing further bytes would emit corrupt frames. The
            # loss is already recorded in the truncated counters.
            if state.pre_101_poisoned:
                return
            if not state.response_headers_seen:
                self._buffer_pre_101(state, direction, msg.body)
                return
            if state.observer is not None:
                for frame in state.observer.observe(
                    direction=direction, chunk=msg.body
                ):
                    self._submit_frame(state, frame, timestamp)
            return

        # One ext_proc HttpBody message may split into several Firehose-sized
        # records; only the very last record of the message carrying
        # ``end_of_stream`` is the terminal chunk of the whole body. Marking it
        # gives the ETL an explicit end-of-body signal the ``num_chunks=0``
        # sentinel format otherwise lacks (a lost trailing chunk would leave
        # the surviving chunk_ids contiguous and indistinguishable from a
        # complete body).
        body_chunks = chunk_body_data(msg.body) or [b""]
        last_index = len(body_chunks) - 1
        for index, body_chunk in enumerate(body_chunks):
            chunk_id = self._next_chunk_id(state, direction)
            self._submit_body_record(
                state=state,
                direction=direction,
                body_bytes=body_chunk,
                timestamp=timestamp,
                chunk_id=chunk_id,
                label=f"{direction.value}_body",
                final_chunk=msg.end_of_stream and index == last_index,
            )

    def _buffer_pre_101(
        self,
        state: _StreamState,
        direction: Direction,
        chunk: bytes,
    ) -> None:
        """Stash a WS body chunk that arrived before the 101 response.

        If adding ``chunk`` would exceed the cap, poison the stream rather
        than truncating mid-frame: a partial frame would desync the parser
        and zlib state on replay, corrupting all later frames. Poisoning
        skips observation and records the loss cleanly.
        """
        if state.pre_101_poisoned:
            return
        if state.pre_101_bytes + len(chunk) > _PRE_101_MAX_BYTES:
            logger.warning(
                "Pre-101 WS buffer cap hit on stream %s (%s): buffered=%d "
                "incoming=%d cap=%d — poisoning stream (frame observation "
                "disabled, loss recorded)",
                state.stream_id,
                direction.value,
                state.pre_101_bytes,
                len(chunk),
                _PRE_101_MAX_BYTES,
            )
            state.pre_101_poisoned = True
            # Count the unobservable bytes as truncated frames per direction
            # so the WSSummaryRecord reflects the audit gap.
            if direction == Direction.REQUEST:
                state.truncated_client_frames += 1
            else:
                state.truncated_server_frames += 1
            state.pre_101_buffer.clear()
            state.pre_101_bytes = 0
            return
        state.pre_101_buffer.append((direction, chunk))
        state.pre_101_bytes += len(chunk)

    def _replay_pre_101(self, state: _StreamState, timestamp: str) -> None:
        """Feed buffered pre-101 bytes through the just-built observer."""
        if state.pre_101_poisoned:
            # Buffer was cleared at poison time; nothing safe to replay.
            return
        if not state.pre_101_buffer or state.observer is None:
            state.pre_101_buffer.clear()
            state.pre_101_bytes = 0
            return
        for direction, chunk in state.pre_101_buffer:
            for frame in state.observer.observe(direction=direction, chunk=chunk):
                self._submit_frame(state, frame, timestamp)
        state.pre_101_buffer.clear()
        state.pre_101_bytes = 0

    def _submit_frame(
        self,
        state: _StreamState,
        frame: ObservedFrame,
        timestamp: str,
    ) -> None:
        """Publish one observed WebSocket frame as a body record."""
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
        if frame.truncated:
            if frame.direction == Direction.REQUEST:
                state.truncated_client_frames += 1
            else:
                state.truncated_server_frames += 1

        # One frame_index per logical WS frame (this whole call), even if the
        # frame's payload is split across multiple body-record chunks below.
        frame_index = self._next_frame_index(state, frame.direction)
        drop_recorded = False
        for body_chunk in chunk_body_data(frame.payload) or [b""]:
            chunk_id = self._next_chunk_id(state, frame.direction)
            accepted = self._submit_body_record(
                state=state,
                direction=frame.direction,
                body_bytes=body_chunk,
                timestamp=timestamp,
                chunk_id=chunk_id,
                label=f"ws_frame_{frame.direction.value}_{frame.opcode}",
                truncated=frame.truncated,
                frame_index=frame_index,
            )
            if not accepted and not drop_recorded:
                if frame.direction == Direction.REQUEST:
                    state.dropped_client_frames += 1
                else:
                    state.dropped_server_frames += 1
                drop_recorded = True

    def _next_chunk_id(self, state: _StreamState, direction: Direction) -> int:
        """Allocate the next body record chunk_id for one direction."""
        if direction == Direction.REQUEST:
            chunk_id = state.request_chunk_id
            state.request_chunk_id += 1
            return chunk_id
        chunk_id = state.response_chunk_id
        state.response_chunk_id += 1
        return chunk_id

    def _next_frame_index(self, state: _StreamState, direction: Direction) -> int:
        """Allocate the next WS frame_index for one direction."""
        if direction == Direction.REQUEST:
            frame_index = state.request_frame_index
            state.request_frame_index += 1
            return frame_index
        frame_index = state.response_frame_index
        state.response_frame_index += 1
        return frame_index

    def _submit_body_record(
        self,
        *,
        state: _StreamState,
        direction: Direction,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        label: str,
        truncated: bool = False,
        final_chunk: bool = False,
        frame_index: Optional[int] = None,
    ) -> bool:
        """Submit one Firehose-sized body record and its drop sentinel.

        ``final_chunk`` marks the terminal chunk of a streamed HTTP body (the
        chunk carrying Envoy's ``end_of_stream``); it lets the Glue ETL detect
        a lost trailing chunk in the ``num_chunks=0`` sentinel wire format.
        ``frame_index`` is set for WS frames (per-frame ordinal, shared by all
        chunks of one frame) and None for HTTP bodies.
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
                    truncated=truncated,
                    final_chunk=final_chunk,
                    frame_index=frame_index,
                ),
                label=label,
            )
        )
        if not accepted:
            logger.warning(
                "Body chunk dropped under queue pressure on stream %s "
                "(%s direction, chunk_id=%d, bytes=%d) — emitting sentinel",
                state.stream_id,
                direction.value,
                chunk_id,
                len(body_bytes),
            )
            # Sentinel body record (empty body, ``dropped=True``, same
            # chunk_id) so downstream ETL sees an explicit gap marker
            # rather than a silent chunk_id discontinuity. Also droppable:
            # the sentinel is tiny so under normal back-pressure it lands
            # where the full record didn't. If even the sentinel drops
            # (true queue saturation), the chunk_id gap + queue counters
            # + this log line remain as the fallback signal.
            self._queue.submit_droppable(
                PublishTask(
                    build=lambda chunk_id=chunk_id: build_method(  # type: ignore[misc]
                        request_id=state.request_id,
                        body_bytes=b"",
                        timestamp=timestamp,
                        chunk_id=chunk_id,
                        num_chunks=0,
                        dropped=True,
                        final_chunk=final_chunk,
                        frame_index=frame_index,
                    ),
                    label=f"{label}_drop_sentinel",
                )
            )
        return accepted

    async def _emit_ws_summary(
        self, state: _StreamState, *, droppable: bool = False
    ) -> None:
        """Build and submit the per-connection WS summary record. Idempotent."""
        if state.summary_emitted:
            return
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
            dropped_client_frames=state.dropped_client_frames,
            dropped_server_frames=state.dropped_server_frames,
            truncated_client_frames=state.truncated_client_frames,
            truncated_server_frames=state.truncated_server_frames,
        )
        task = PublishTask(
            build=lambda: self._publish.build_ws_summary(record=record),
            label="ws_summary",
        )
        if droppable:
            self._queue.submit_droppable(task)
        else:
            await self._queue.submit_blocking(task)
        state.summary_emitted = True


def _extract_request_id(req: proc_pb2.ProcessingRequest) -> str:
    """Read x-request-id from the first headers message, or mint one."""
    if req.HasField("request_headers"):
        for h in req.request_headers.headers.headers:
            if h.key.lower() == "x-request-id":
                value = _header_value(h)
                if value:
                    return value
    return str(uuid.uuid4())


def _header_value_bytes(h) -> bytes:
    """Read the populated value out of an Envoy HeaderValue as raw bytes.

    ``raw_value`` wins when both are set. Warns on divergence with byte
    counts only — header keys + content could leak credentials.
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


def _extract_mode(req: proc_pb2.ProcessingRequest) -> StreamMode:
    """Detect WS-upgrade vs plain-HTTP from the first ProcessingRequest."""
    # filter_metadata path (forward-compat: stock Envoy doesn't populate
    # this for route-level metadata, but a future set_metadata filter could).
    try:
        metadata = req.metadata_context.filter_metadata.get(_METADATA_NS)
        if metadata is not None:
            ws = metadata.fields.get(_WS_METADATA_KEY)
            if ws is not None and ws.bool_value:
                return StreamMode.WS_UPGRADE
    except Exception:
        pass

    # ``upgrade: websocket`` on the request_headers event — the reliable
    # RFC 6455 signal across every Envoy version.
    if req.HasField("request_headers"):
        for h in req.request_headers.headers.headers:
            if h.key.lower() == "upgrade":
                if _header_value(h).lower() == "websocket":
                    return StreamMode.WS_UPGRADE
                break
    return StreamMode.HTTP


def _extract_auth_metadata(
    req: proc_pb2.ProcessingRequest,
) -> tuple[Optional[dict], Optional[str]]:
    """Pull ``principal_info`` + ``secret_arn`` from ext_authz dynamic_metadata.

    Returns ``(None, None)`` when ext_authz is disabled on the route
    (e.g. /ping).
    """
    try:
        ns = req.metadata_context.filter_metadata.get(_AUTH_METADATA_NS)
    except Exception:
        return None, None
    if ns is None:
        return None, None

    principal_info: Optional[dict] = None
    pi_value = ns.fields.get(_AUTH_PRINCIPAL_INFO_KEY)
    if pi_value is not None and pi_value.HasField("struct_value"):
        principal_info = MessageToDict(pi_value.struct_value)

    secret_arn: Optional[str] = None
    sa_value = ns.fields.get(_AUTH_SECRET_ARN_KEY)
    if sa_value is not None and sa_value.HasField("string_value"):
        secret_arn = sa_value.string_value

    return principal_info, secret_arn


def _header_value(h) -> str:
    """Return ``_header_value_bytes`` decoded as UTF-8 with replacement."""
    return _header_value_bytes(h).decode("utf-8", errors="replace")


_REDACTED_HEADERS: frozenset[str] = frozenset(
    {
        config.api_key_header.lower(),
        "x-api-key",
        # Session credentials and second-factor bearer tokens — clients
        # can ship these alongside the api-key header.
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-amz-security-token",
    }
)


def _headers_to_dict(http_headers: base_pb2.HeaderMap) -> dict[str, str]:
    """Flatten Envoy's HeaderMap into a case-folded dict of base64 values.

    Drops headers in :data:`_REDACTED_HEADERS` (the configured API-key
    header plus ``x-api-key``) — ext_proc observes headers *after*
    ext_authz has rewritten them to the real upstream provider key, so
    publishing them verbatim would archive customer secrets to Firehose.
    Matches the legacy Lua filter's exclusion on ``api_key_header``.

    Base64 operates on raw bytes (not UTF-8-decoded text) so non-UTF-8
    values survive the wire round-trip losslessly. Glue ETL calls
    ``_decode_b64_header`` on these values.
    """
    return {
        h.key.lower(): base64.b64encode(_header_value_bytes(h)).decode("ascii")
        for h in http_headers.headers
        if h.key.lower() not in _REDACTED_HEADERS
    }


def _empty_headers_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """No-op headers response — required even when not mutating."""
    hdr = proc_pb2.HeadersResponse(response=proc_pb2.CommonResponse())
    if request_side:
        return proc_pb2.ProcessingResponse(request_headers=hdr)
    return proc_pb2.ProcessingResponse(response_headers=hdr)


def _empty_trailers_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """No-op trailers response — required even when not mutating."""
    tr = proc_pb2.TrailersResponse()
    if request_side:
        return proc_pb2.ProcessingResponse(request_trailers=tr)
    return proc_pb2.ProcessingResponse(response_trailers=tr)
