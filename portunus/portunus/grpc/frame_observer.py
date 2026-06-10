"""WebSocket frame observer for ext_proc streams.

Wraps :mod:`wsproto` to surface logical WebSocket frames from raw,
possibly-fragmented, possibly-deflate-compressed bytes carried over
``ext_proc`` body events for upgraded streams.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Iterator, Optional

from wsproto.connection import Connection, ConnectionType
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason

logger = logging.getLogger("api.access")


class Direction(Enum):
    """Stream direction for frame observation."""

    REQUEST = "request"  # client → server
    RESPONSE = "response"  # server → client


@dataclass
class ObservedFrame:
    """A single logical WebSocket frame extracted from raw bytes."""

    direction: Direction
    opcode: str
    payload: bytes
    close_code: Optional[int] = None
    truncated: bool = False


# Zip-bomb cap: permessage-deflate can hit 1000:1 ratios on repetitive
# text. 16 MiB is comfortably above realistic WS payloads.
MAX_DECOMPRESSED_PAYLOAD_BYTES = 16 * 1024 * 1024


class _CappedPerMessageDeflate(PerMessageDeflate):
    """``PerMessageDeflate`` with a per-message inflated-byte cap.

    Stock wsproto calls ``zlib.decompressobj.decompress(data)`` with no
    ``max_length`` — a hostile frame at a 1000:1 ratio can allocate
    hundreds of megabytes before the post-hoc ``_capped`` check fires.
    This subclass uses ``max_length`` on every decompress call and
    tracks cumulative inflated bytes for the current message; when the
    cap is exceeded, it returns ``CloseReason.MESSAGE_TOO_BIG`` so
    wsproto aborts the frame rather than buffering more.
    """

    def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self._inflated_in_message = 0

    def frame_inbound_payload_data(self, proto, data):  # type: ignore[no-untyped-def]
        if not self._inbound_compressed or not self._inbound_is_compressible:
            return data
        assert self._decompressor is not None
        remaining = MAX_DECOMPRESSED_PAYLOAD_BYTES - self._inflated_in_message
        if remaining <= 0:
            return CloseReason.MESSAGE_TOO_BIG
        try:
            inflated = self._decompressor.decompress(bytes(data), remaining)
        except Exception:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA
        self._inflated_in_message += len(inflated)
        if self._decompressor.unconsumed_tail:
            # Cap fired — wsproto would otherwise re-feed this on the
            # next call, ballooning memory. Abort the connection.
            return CloseReason.MESSAGE_TOO_BIG
        return inflated

    def frame_inbound_complete(self, proto, fin):  # type: ignore[no-untyped-def]
        result = super().frame_inbound_complete(proto, fin)
        if fin:
            self._inflated_in_message = 0
        return result


def _negotiated_deflate(extensions_header: Optional[str]) -> bool:
    """Return True if the upstream 101 negotiated permessage-deflate."""
    if not extensions_header:
        return False
    return "permessage-deflate" in extensions_header.lower()


def _make_finalized_deflate(extensions_header: str) -> "PerMessageDeflate":
    """Build a capped :class:`PerMessageDeflate` already in the enabled state.

    Workaround for a wsproto quirk: when we instantiate ``Connection``
    directly in OPEN state, the handshake state machine never runs, so
    ``PerMessageDeflate._enabled`` stays False and every RSV1 frame is
    rejected as "Reserved bit set unexpectedly". Calling ``finalize()``
    with the negotiated params flips ``_enabled`` true.
    """
    ext = _CappedPerMessageDeflate()
    ext.finalize(extensions_header)
    return ext


def build_observer(
    *,
    response_extensions_header: Optional[str],
) -> "FrameObserver":
    """Construct a :class:`FrameObserver` for the negotiated extensions."""
    deflate = _negotiated_deflate(response_extensions_header)
    # zlib state is per-direction; each direction owns its own extension.
    extensions_req: list = (
        [_make_finalized_deflate(response_extensions_header or "")] if deflate else []
    )
    extensions_resp: list = (
        [_make_finalized_deflate(response_extensions_header or "")] if deflate else []
    )
    return FrameObserver(
        request_conn=Connection(ConnectionType.SERVER, extensions=extensions_req),
        response_conn=Connection(ConnectionType.CLIENT, extensions=extensions_resp),
    )


class FrameObserver:
    """Stateful frame parser for one upgraded WebSocket connection.

    Holds one ``wsproto.Connection`` per direction because permessage-deflate
    zlib state is per-direction. Not thread-safe.
    """

    def __init__(
        self,
        *,
        request_conn: Connection,
        response_conn: Connection,
    ) -> None:
        self._request = request_conn
        self._response = response_conn

    def observe(
        self,
        *,
        direction: Direction,
        chunk: bytes,
    ) -> Iterator[ObservedFrame]:
        """Feed a raw byte chunk in one direction and yield observed frames."""
        conn = self._request if direction == Direction.REQUEST else self._response
        try:
            conn.receive_data(chunk)
        except Exception as e:
            # wsproto error messages can echo offending frame bytes —
            # log the exception class only. Stop observing this direction
            # rather than killing the stream.
            logger.warning(
                "wsproto frame-parse error on %s direction: %s",
                direction.value,
                type(e).__name__,
            )
            return

        for event in conn.events():
            yield from self._map_event(direction, event)

    @staticmethod
    def _map_event(direction: Direction, event) -> Iterator[ObservedFrame]:
        """Convert a wsproto event into one or more :class:`ObservedFrame`."""
        if isinstance(event, TextMessage):
            payload = (
                event.data.encode("utf-8")
                if isinstance(event.data, str)
                else event.data
            )
            yield _capped(direction, "text", payload)
        elif isinstance(event, BytesMessage):
            yield _capped(direction, "binary", event.data)
        elif isinstance(event, Ping):
            yield ObservedFrame(
                direction=direction, opcode="ping", payload=event.payload
            )
        elif isinstance(event, Pong):
            yield ObservedFrame(
                direction=direction, opcode="pong", payload=event.payload
            )
        elif isinstance(event, CloseConnection):
            yield ObservedFrame(
                direction=direction,
                opcode="close",
                payload=(event.reason or "").encode("utf-8"),
                close_code=event.code,
            )


def _capped(direction: Direction, opcode: str, payload: bytes) -> ObservedFrame:
    """Truncate oversize data-message payloads with a ``truncated=True`` flag."""
    if len(payload) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
        logger.warning(
            "Truncating oversize WS %s frame on %s direction: %d > %d bytes",
            opcode,
            direction.value,
            len(payload),
            MAX_DECOMPRESSED_PAYLOAD_BYTES,
        )
        return ObservedFrame(
            direction=direction,
            opcode=opcode,
            payload=payload[:MAX_DECOMPRESSED_PAYLOAD_BYTES],
            truncated=True,
        )
    return ObservedFrame(direction=direction, opcode=opcode, payload=payload)
