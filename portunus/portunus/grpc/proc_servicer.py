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
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Optional

import grpc
from envoy.config.core.v3 import base_pb2  # type: ignore[import-not-found]
from envoy.service.ext_proc.v3 import (  # type: ignore[import-not-found]
    external_processor_pb2 as proc_pb2,
    external_processor_pb2_grpc as proc_grpc,
)

from portunus.config import config
from portunus.grpc.frame_observer import (
    Direction,
    FrameObserver,
    ObservedFrame,
    build_observer,
)
from portunus.grpc.proxy_auth import extract_proxy_key, is_valid_proxy_key
from portunus.grpc.publish_queue import BoundedPublishQueue, PublishTask
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

    request_id: str
    mode: StreamMode
    observer: Optional[FrameObserver] = None
    upstream_extensions: Optional[str] = None
    drain_requested: asyncio.Event = field(default_factory=asyncio.Event)


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
        # Active streams indexed by request_id so the drain handler can
        # iterate and inject close frames.
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
                    self._active[state.request_id] = state

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
                self._active.pop(state.request_id, None)

    # ------------------------------------------------------------------
    # Stream setup
    # ------------------------------------------------------------------

    def _initialise_stream(
        self, first: proc_pb2.ProcessingRequest
    ) -> _StreamState:
        """Inspect the first ProcessingRequest and build per-stream state."""
        request_id = _extract_request_id(first)
        mode = _extract_mode(first)
        observer = build_observer(response_extensions_header=None) if mode == StreamMode.WS_UPGRADE else None
        return _StreamState(request_id=request_id, mode=mode, observer=observer)

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
            yield _empty_body_response(request_side=True)
        elif request.HasField("request_body"):
            self._on_body_chunk(
                state, request.request_body, direction=Direction.REQUEST, timestamp=timestamp
            )
            yield _empty_body_response(request_side=True)
        elif request.HasField("request_trailers"):
            await self._on_request_trailers(state, request.request_trailers, timestamp)
            yield _empty_trailers_response(request_side=True)
        elif request.HasField("response_headers"):
            await self._on_response_headers(state, request.response_headers, timestamp)
            yield _empty_body_response(request_side=False)
        elif request.HasField("response_body"):
            self._on_body_chunk(
                state, request.response_body, direction=Direction.RESPONSE, timestamp=timestamp
            )
            yield _empty_body_response(request_side=False)
        elif request.HasField("response_trailers"):
            await self._on_response_trailers(state, request.response_trailers, timestamp)
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
                state, msg.body, direction=direction, timestamp=timestamp
            )

    def _submit_http_body(
        self,
        state: _StreamState,
        body: bytes,
        *,
        direction: Direction,
        timestamp: str,
    ) -> None:
        publish_method = (
            self._publish.publish_request_body
            if direction == Direction.REQUEST
            else self._publish.publish_response_body
        )
        self._queue.submit_droppable(
            PublishTask(
                coro_fn=lambda: publish_method(
                    request_id=state.request_id,
                    body_bytes=body,
                    timestamp=timestamp,
                    chunk_id=0,
                    num_chunks=1,
                ),
                label=f"{direction.value}_body",
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
                return h.value
    return str(uuid.uuid4())


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
    in ``portunus.models`` (and the joined-log ETL downstream) call
    ``_decode_b64_header`` on these values to populate the convenience
    fields (``path``, ``authority``, ``status``, etc.) that aisitok's
    provider detection consumes. Sending raw strings here would break
    every header record once it lands in Kinesis.
    """
    import base64

    return {
        h.key.lower(): base64.b64encode(h.value.encode("utf-8")).decode("ascii")
        for h in http_headers.headers
    }


def _empty_body_response(*, request_side: bool) -> proc_pb2.ProcessingResponse:
    """The body response shape Envoy 1.36 requires in FDS mode.

    A bare ``CommonResponse()`` triggers "Spurious response message 3"
    and tears the connection. The fix is the doubly-nested empty
    streamed_response marker.
    """
    body_response = proc_pb2.BodyResponse(
        response=proc_pb2.CommonResponse(
            body_mutation=proc_pb2.BodyMutation(
                streamed_response=proc_pb2.StreamedBodyResponse()
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
