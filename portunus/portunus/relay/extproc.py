"""ext_proc WebSocket relay handler.

Replaces the legacy in-process Python relay with an Envoy ext_proc filter
in FULL_DUPLEX_STREAMED mode. Envoy proxies the WS data path itself; this
gRPC servicer observes post-upgrade frames for per-message Kinesis logging.

Auth happens upstream of ext_proc, in Envoy's Lua filter, exactly as it
does for HTTP — Lua sub-calls the existing /authorise endpoint, gets back
the real provider API key, and rewrites the Authorization header before
the WS upgrade is forwarded. By the time ext_proc sees request_headers,
auth is already done; we just observe.

Frames are parsed in-process so the existing Kinesis schema (one record
per logical WS message, with permessage-deflate already inflated) is
preserved. Downstream consumers (aisitok, Glue) get the same shape they
do today from the legacy relay.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator

import grpc
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import (
    external_processor_pb2 as ep_pb,
)
from envoy.service.ext_proc.v3 import (
    external_processor_pb2_grpc as ep_grpc,
)
from wsproto.connection import Connection, ConnectionType
from wsproto.events import BytesMessage, CloseConnection, TextMessage
from wsproto.extensions import Extension, PerMessageDeflate

from portunus.relay.logger import enqueue_log, log_ws_summary
from portunus.services.publish_service import PublishService

logger = logging.getLogger("api.access")


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------


def _build_extensions(extensions_header: str) -> list[Extension]:
    """Instantiate wsproto extensions matching what the upstream negotiated.

    Only permessage-deflate is implemented — it covers ~all production
    traffic. Each direction needs its own instance because PerMessageDeflate
    carries zlib state.
    """
    if not extensions_header:
        return []
    out: list[Extension] = []
    for offer in extensions_header.split(","):
        offer = offer.strip()
        if not offer:
            continue
        name = offer.split(";", 1)[0].strip()
        if name == PerMessageDeflate.name:
            ext = PerMessageDeflate()
            ext.finalize(offer)
            out.append(ext)
    return out


class _FrameObserver:
    """Sans-IO frame parser for one direction of the upgraded connection.

    Uses wsproto's lower-level Connection (post-handshake parser) directly,
    starting in OPEN state. Buffers fragmented messages so callers see only
    completed Text/BytesMessage events with full payloads.
    """

    def __init__(self, conn_type: ConnectionType, extensions: list[Extension]) -> None:
        self._conn = Connection(conn_type, extensions=extensions)
        self._text_buf: str | None = None
        self._bytes_buf: bytearray | None = None

    def feed(self, chunk: bytes) -> list[object]:
        self._conn.receive_data(chunk)
        emitted: list[object] = []
        for ev in self._conn.events():
            if isinstance(ev, TextMessage):
                self._text_buf = (self._text_buf or "") + ev.data
                if ev.message_finished:
                    emitted.append(
                        TextMessage(
                            data=self._text_buf,
                            frame_finished=True,
                            message_finished=True,
                        )
                    )
                    self._text_buf = None
            elif isinstance(ev, BytesMessage):
                if self._bytes_buf is None:
                    self._bytes_buf = bytearray()
                self._bytes_buf.extend(ev.data)
                if ev.message_finished:
                    emitted.append(
                        BytesMessage(
                            data=bytes(self._bytes_buf),
                            frame_finished=True,
                            message_finished=True,
                        )
                    )
                    self._bytes_buf = None
            else:
                emitted.append(ev)
        return emitted


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_headers(header_map: base_pb2.HeaderMap) -> dict[str, str]:
    """Lowercase-keyed view of an Envoy HeaderMap."""
    return {
        h.key.lower(): h.raw_value.decode("utf-8", errors="replace")
        for h in header_map.headers
    }


def _passthrough_body(
    *, direction: str, chunk: bytes, end_of_stream: bool
) -> ep_pb.ProcessingResponse:
    """Echo body bytes back to Envoy unmodified.

    Required shape for FULL_DUPLEX_STREAMED — empty CommonResponse triggers
    Envoy's "spurious response message" failure.
    """
    body_response = ep_pb.BodyResponse(
        response=ep_pb.CommonResponse(
            body_mutation=ep_pb.BodyMutation(
                streamed_response=ep_pb.StreamedBodyResponse(
                    body=chunk, end_of_stream=end_of_stream
                )
            )
        )
    )
    if direction == "client_to_upstream":
        return ep_pb.ProcessingResponse(request_body=body_response)
    return ep_pb.ProcessingResponse(response_body=body_response)


# ---------------------------------------------------------------------------
# The servicer
# ---------------------------------------------------------------------------


class ExtProcRelayServicer(ep_grpc.ExternalProcessorServicer):
    """ExternalProcessor servicer: observes WS frames, publishes per-message logs."""

    def __init__(self, publish_service: PublishService) -> None:
        self._publish = publish_service

    async def Process(  # noqa: N802 — gRPC method name
        self,
        request_iterator: AsyncIterator[ep_pb.ProcessingRequest],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[ep_pb.ProcessingResponse]:
        request_id: str | None = None
        c2u: _FrameObserver | None = None
        u2c: _FrameObserver | None = None
        client_msgs = 0
        upstream_msgs = 0
        close_code: int | None = None
        started_at = time.monotonic()

        try:
            async for req in request_iterator:
                kind = req.WhichOneof("request")

                if kind == "request_headers":
                    headers = _decode_headers(req.request_headers.headers)
                    # Envoy adds x-request-id when generate_request_id is on; the
                    # Lua filter sets it as well. Either way it's our trace key.
                    request_id = headers.get("x-request-id", "<no-request-id>")
                    yield ep_pb.ProcessingResponse(
                        request_headers=ep_pb.HeadersResponse()
                    )

                elif kind == "response_headers":
                    headers = _decode_headers(req.response_headers.headers)
                    if headers.get(":status") == "101":
                        ext_header = headers.get("sec-websocket-extensions", "")
                        c2u = _FrameObserver(
                            ConnectionType.SERVER, _build_extensions(ext_header)
                        )
                        u2c = _FrameObserver(
                            ConnectionType.CLIENT, _build_extensions(ext_header)
                        )
                    yield ep_pb.ProcessingResponse(
                        response_headers=ep_pb.HeadersResponse()
                    )

                elif kind == "request_body":
                    chunk = req.request_body.body
                    end = req.request_body.end_of_stream
                    if c2u is not None and chunk and request_id is not None:
                        client_msgs, code_seen = await self._observe(
                            c2u, chunk, "client_to_upstream", request_id, client_msgs
                        )
                        if code_seen is not None:
                            close_code = code_seen
                    yield _passthrough_body(
                        direction="client_to_upstream", chunk=chunk, end_of_stream=end
                    )

                elif kind == "response_body":
                    chunk = req.response_body.body
                    end = req.response_body.end_of_stream
                    if u2c is not None and chunk and request_id is not None:
                        upstream_msgs, code_seen = await self._observe(
                            u2c, chunk, "upstream_to_client", request_id, upstream_msgs
                        )
                        if code_seen is not None and close_code is None:
                            close_code = code_seen
                    yield _passthrough_body(
                        direction="upstream_to_client", chunk=chunk, end_of_stream=end
                    )

                else:
                    yield ep_pb.ProcessingResponse()

        finally:
            if request_id is not None:
                duration = time.monotonic() - started_at
                await log_ws_summary(
                    self._publish,
                    request_id,
                    client_messages=client_msgs,
                    upstream_messages=upstream_msgs,
                    duration_seconds=duration,
                    close_code=close_code,
                )

    async def _observe(
        self,
        observer: _FrameObserver,
        chunk: bytes,
        direction: str,
        request_id: str,
        message_count: int,
    ) -> tuple[int, int | None]:
        """Feed a body chunk through the observer; publish completed messages."""
        close_code: int | None = None
        for ev in observer.feed(chunk):
            if isinstance(ev, (TextMessage, BytesMessage)) and ev.message_finished:
                message_count += 1
                payload = (
                    ev.data.encode("utf-8") if isinstance(ev, TextMessage) else ev.data
                )
                await enqueue_log(
                    self._publish, request_id, direction, payload, message_count
                )
            elif isinstance(ev, CloseConnection):
                close_code = ev.code
        return message_count, close_code
