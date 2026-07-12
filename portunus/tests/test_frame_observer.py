"""Tests for ``FrameObserver``'s defensive caps.

The observer bounds per-frame decompressed WS payload size; without the cap a
tiny permessage-deflate frame can decompress to many MB and OOM the process.
"""

from __future__ import annotations

from wsproto.connection import Connection, ConnectionType
from wsproto.events import TextMessage

from portunus.grpc.frame_observer import (
    MAX_DECOMPRESSED_PAYLOAD_BYTES,
    Direction,
    ObservedFrame,
    _capped,
    _make_finalized_deflate,
    build_observer,
)


def test_capped_passes_through_payloads_under_the_cap():
    """Small payloads survive intact with ``truncated=False``."""
    payload = b"hello world"
    frame = _capped(Direction.REQUEST, "text", payload)
    assert frame.payload == payload
    assert frame.truncated is False


def test_capped_truncates_oversize_payloads_and_sets_the_flag():
    """Anything above ``MAX_DECOMPRESSED_PAYLOAD_BYTES`` is sliced and the.

    ``truncated`` flag set (downstream's only signal it was capped).
    """
    payload = b"X" * (MAX_DECOMPRESSED_PAYLOAD_BYTES + 1024)
    frame = _capped(Direction.RESPONSE, "binary", payload)
    assert len(frame.payload) == MAX_DECOMPRESSED_PAYLOAD_BYTES
    assert frame.truncated is True


def test_observed_frame_default_truncated_is_false():
    """Existing constructions that don't pass ``truncated`` stay un-flagged."""
    frame = ObservedFrame(
        direction=Direction.REQUEST,
        opcode="text",
        payload=b"ok",
    )
    assert frame.truncated is False


def test_finalized_deflate_observer_accepts_compressed_frames():
    """Regression: ``_make_finalized_deflate`` must drive the wsproto extension.

    through ``finalize()`` so RSV1 deflate frames aren't rejected as "Reserved
    bit set unexpectedly" (without it the extension stays ``_enabled=False``).
    """
    extensions_header = "permessage-deflate; client_no_context_takeover"

    plaintext = "hello deflated world " * 32
    sender = Connection(
        ConnectionType.CLIENT,
        extensions=[_make_finalized_deflate(extensions_header)],
    )
    frame_bytes = sender.send(TextMessage(plaintext))

    observer = build_observer(response_extensions_header=extensions_header)
    frames = list(observer.observe(direction=Direction.REQUEST, chunk=frame_bytes))

    assert len(frames) == 1
    assert frames[0].opcode == "text"
    assert frames[0].payload == plaintext.encode("utf-8")


def _ws_text_frame(payload: bytes) -> bytes:
    """Single-fragment, unmasked WS text frame (server->client direction)."""
    return bytes([0x81, len(payload)]) + payload


def _masked_ws_text_frame(payload: bytes) -> bytes:
    """Single-fragment, masked WS text frame (client->server direction).

    The REQUEST-direction connection is ``ConnectionType.SERVER`` and rejects
    unmasked client frames per RFC 6455.
    """
    mask = b"\x01\x02\x03\x04"
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes([0x81, 0x80 | len(payload)]) + mask + masked


def test_parse_error_desyncs_its_direction_only_and_flags_lost_frames():
    """A malformed frame desyncs its direction; the loss is flagged once.

    wsproto swallows the ``ParseFailed`` and synthesizes a CloseConnection
    without leaving OPEN (the discriminator from a genuine close), then drops
    every further byte in that direction. ``desynced`` is the caller's only
    signal; the synthesized close must NOT surface as an observed close frame.
    """
    observer = build_observer(response_extensions_header=None)

    # 0x8F = FIN + reserved opcode 0xF → ParseFailed inside wsproto.
    malformed = bytes([0x8F, 0x02]) + b"xx"
    frames = list(observer.observe(direction=Direction.RESPONSE, chunk=malformed))
    assert frames == []  # no fake close frame
    assert observer.desynced(Direction.RESPONSE) is True
    assert observer.desynced(Direction.REQUEST) is False

    # The poisoned direction yields nothing ever again — and doesn't raise.
    frames = list(
        observer.observe(direction=Direction.RESPONSE, chunk=_ws_text_frame(b"hi"))
    )
    assert frames == []

    # The healthy direction is unaffected.
    frames = list(
        observer.observe(
            direction=Direction.REQUEST, chunk=_masked_ws_text_frame(b"ok")
        )
    )
    assert [f.payload for f in frames] == [b"ok"]
    assert observer.desynced(Direction.REQUEST) is False


def test_genuine_close_frame_is_still_observed_not_treated_as_desync():
    """A real wire close frame must still surface as a close ObservedFrame.

    Parse-failure detection keys on CloseConnection yielded while still OPEN; a
    genuine close moves the state first, so it must keep flowing through.
    """
    observer = build_observer(response_extensions_header=None)
    # Unmasked close frame (server->client): FIN+opcode 0x8, 2-byte code
    # 1000 (normal closure).
    close_frame = bytes([0x88, 0x02]) + (1000).to_bytes(2, "big")

    frames = list(observer.observe(direction=Direction.RESPONSE, chunk=close_frame))

    assert [f.opcode for f in frames] == ["close"]
    assert frames[0].close_code == 1000
    assert observer.desynced(Direction.RESPONSE) is False


def test_frames_parsed_before_the_poison_byte_are_still_yielded():
    """A chunk of [valid frame][garbage] yields the valid frame, and flags.

    the desync in the same call.
    """
    observer = build_observer(response_extensions_header=None)
    chunk = _ws_text_frame(b"good") + bytes([0x8F, 0x00])

    frames = list(observer.observe(direction=Direction.RESPONSE, chunk=chunk))

    assert [(f.opcode, f.payload) for f in frames] == [("text", b"good")]
    assert observer.desynced(Direction.RESPONSE) is True
