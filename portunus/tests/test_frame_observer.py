"""Tests for ``FrameObserver``'s defensive caps.

The observer wraps wsproto so per-frame WS payloads (post-deflate)
have a bounded size. Without the cap, a hostile client can use
permessage-deflate's high compression ratio to send a tiny frame
that decompresses to many MB — that would OOM the process and
cascade fail-closed on every in-flight stream's ext_authz call.
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
    """Anything above ``MAX_DECOMPRESSED_PAYLOAD_BYTES`` is sliced.

    Reading the original ``len(payload)`` after this call is the only
    way downstream can know the payload was capped — hence the
    ``truncated`` flag on ``ObservedFrame``.
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
    """Regression: ``_make_finalized_deflate`` must drive the wsproto.

    extension through ``finalize()`` so RSV1 frames (the deflate flag)
    aren't rejected as "Reserved bit set unexpectedly". Without
    ``finalize`` the extension stays in ``_enabled=False`` and every
    deflate-compressed text frame trips the reserved-bit check.

    Build a sender with the same finalized deflate extension wsproto
    uses internally for permessage-deflate, encode a real compressed
    frame, then feed those bytes to the observer and confirm the text
    payload comes out decompressed.
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
