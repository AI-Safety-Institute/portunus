"""WebSocket frame observer for ext_proc streams.

When Envoy's ``ext_proc`` filter is in ``FULL_DUPLEX_STREAMED`` mode on
an upgraded WebSocket connection, body bytes arriving from each
direction are raw WebSocket-protocol bytes — framed, possibly fragmented,
possibly compressed via ``permessage-deflate``. This module wraps
:mod:`wsproto` to surface logical frames as
:class:`ObservedFrame` events the Process service can publish.

Key behaviours that survived prototyping:

- Use :class:`wsproto.connection.Connection` directly, not the
  ``WSConnection`` wrapper. The wrapper starts in ``CONNECTING`` state
  and refuses frame parsing until handshake; the underlying
  ``Connection`` starts in ``OPEN``, which is what ext_proc observes
  post-101.

- Per-direction PerMessageDeflate state. zlib state is per-direction —
  the client→server and server→client streams must each have their
  own :class:`PerMessageDeflate` extension instance.

- The handler reads ``Sec-WebSocket-Extensions`` from the upstream's
  ``101 Switching Protocols`` response headers (delivered to
  ``response_headers`` in the ext_proc stream) and decides whether to
  enable deflate per direction based on what was negotiated.
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

logger = logging.getLogger("api.access")


class Direction(Enum):
    """Stream direction for frame observation."""

    REQUEST = "request"  # client → server
    RESPONSE = "response"  # server → client


@dataclass
class ObservedFrame:
    """A single logical WebSocket frame extracted from raw bytes.

    Attributes:
        direction: Which leg of the connection the frame belongs to.
        opcode: Loose opcode string — "text", "binary", "ping", "pong",
            or "close". Control frames are surfaced so the audit trail
            shows ping/pong storms and close codes.
        payload: The frame's payload bytes. For text frames this is the
            UTF-8-encoded message. For control frames it's the control
            payload (close code + reason, ping/pong payload, etc.).
        close_code: Populated for ``close`` frames; otherwise ``None``.
    """

    direction: Direction
    opcode: str
    payload: bytes
    close_code: Optional[int] = None


def _negotiated_deflate(extensions_header: Optional[str]) -> bool:
    """Return True if the upstream's 101 response negotiated permessage-deflate."""
    if not extensions_header:
        return False
    return "permessage-deflate" in extensions_header.lower()


def build_observer(
    *,
    response_extensions_header: Optional[str],
) -> "FrameObserver":
    """Construct a :class:`FrameObserver` given the upstream's negotiated extensions.

    ``response_extensions_header`` is the value of
    ``Sec-WebSocket-Extensions`` from the upstream's 101 Switching
    Protocols response, or ``None`` if the upstream didn't advertise
    any extensions.
    """
    deflate = _negotiated_deflate(response_extensions_header)
    extensions_req: list = [PerMessageDeflate()] if deflate else []
    extensions_resp: list = [PerMessageDeflate()] if deflate else []
    return FrameObserver(
        request_conn=Connection(ConnectionType.SERVER, extensions=extensions_req),
        response_conn=Connection(ConnectionType.CLIENT, extensions=extensions_resp),
    )


class FrameObserver:
    """Stateful frame parser for one upgraded WebSocket connection.

    Two ``wsproto.Connection`` instances are held — one per direction —
    because zlib state for ``permessage-deflate`` is per-direction.
    Sharing a single connection would silently corrupt frames once
    the second direction's deflate stream advanced its zlib state.

    The class is not thread-safe; each upgraded connection should have
    its own observer, and observations of a given direction must be
    serialised.
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
        """Feed a raw byte chunk in one direction and yield observed frames.

        ``chunk`` is the body bytes from one ``ProcessingRequest`` — wsproto
        is buffered, so a chunk that contains a partial frame yields no
        events; subsequent chunks complete and yield together.
        """
        conn = self._request if direction == Direction.REQUEST else self._response
        try:
            conn.receive_data(chunk)
        except Exception as e:
            # Malformed frame from a buggy client / upstream. Don't kill
            # the stream — just stop observing this direction and let
            # Envoy continue forwarding the bytes opaquely.
            logger.warning(
                "wsproto frame-parse error on %s direction: %s", direction.value, e
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
            yield ObservedFrame(direction=direction, opcode="text", payload=payload)
        elif isinstance(event, BytesMessage):
            yield ObservedFrame(
                direction=direction, opcode="binary", payload=event.data
            )
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
        # Other events (e.g. AcceptConnection, RejectConnection) are
        # handshake-only and shouldn't appear once we're in OPEN state.
