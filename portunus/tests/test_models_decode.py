"""Tests for ``_decompress_b64_body``: plain, gzip/deflate, eventstream."""

import base64
import binascii
import gzip
import json
import logging
import struct
import zlib

import pytest

from portunus.models import (
    _decompress_b64_body,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _build_eventstream_message(payload: bytes, headers: bytes = b"") -> bytes:
    """[12-byte prelude][headers][payload][4-byte CRC] with valid CRC32s.

    Mirrors the vnd.amazon.eventstream wire format botocore's
    ``EventStreamBuffer`` parses: the prelude carries a CRC32 of its first
    8 bytes, and the message ends with a CRC32 of everything preceding it.
    """
    total_len = 12 + len(headers) + len(payload) + 4
    prelude_head = struct.pack(">II", total_len, len(headers))
    prelude_crc = binascii.crc32(prelude_head) & 0xFFFFFFFF
    message_no_crc = prelude_head + struct.pack(">I", prelude_crc) + headers + payload
    message_crc = binascii.crc32(message_no_crc) & 0xFFFFFFFF
    return message_no_crc + struct.pack(">I", message_crc)


def _bedrock_event(inner_obj: dict, headers: bytes = b"") -> bytes:
    """One eventstream message wrapping an Anthropic-shaped inner event."""
    inner_json = json.dumps(inner_obj, separators=(",", ":"))
    payload = json.dumps({"bytes": _b64(inner_json.encode("utf-8"))}).encode("utf-8")
    return _build_eventstream_message(payload, headers)


def _eventstream_envelope(envelope: dict) -> bytes:
    payload = json.dumps(envelope).encode("utf-8")
    return _build_eventstream_message(payload)


def _bedrock_raw_inner(inner_json: str) -> bytes:
    return _eventstream_envelope({"bytes": _b64(inner_json.encode("utf-8"))})


def test_plain_utf8_passes_through():
    body = '{"hello": "world"}'
    decoded, failed = _decompress_b64_body(_b64(body.encode()), None)
    assert not failed
    assert decoded == body


def test_gzip_content_encoding_decompresses():
    body = '{"hello": "world"}'
    decoded, failed = _decompress_b64_body(_b64(gzip.compress(body.encode())), "gzip")
    assert not failed
    assert decoded == body


def test_deflate_content_encoding_decompresses():
    body = '{"hello": "world"}'
    decoded, failed = _decompress_b64_body(
        _b64(zlib.compress(body.encode())), "deflate"
    )
    assert not failed
    assert decoded == body


def test_invalid_base64_marks_failure():
    decoded, failed = _decompress_b64_body("!!!not-base64!!!", None)
    assert failed
    assert decoded is None


def test_corrupt_gzip_marks_failure():
    decoded, failed = _decompress_b64_body(_b64(b"not gzip"), "gzip")
    assert failed
    assert decoded is None


def test_non_utf8_bytes_mark_failure_when_no_eventstream_hint():
    decoded, failed = _decompress_b64_body(_b64(b"\xff\xfe\xfd\x00"), None)
    assert failed
    assert decoded is None


def test_eventstream_single_message():
    inner = {"type": "message_start", "message": {"usage": {"input_tokens": 10}}}
    es_bytes = _bedrock_event(inner)
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == f"data: {json.dumps(inner, separators=(',', ':'))}\n"


def test_eventstream_multiple_messages_concatenated():
    events = [
        {"type": "message_start", "message": {"usage": {"input_tokens": 42}}},
        {"type": "content_block_delta", "delta": {"text": "hi"}},
        {"type": "message_delta", "usage": {"output_tokens": 7}},
    ]
    es_bytes = b"".join(_bedrock_event(e) for e in events)
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    expected = "".join(
        f"data: {json.dumps(e, separators=(',', ':'))}\n" for e in events
    )
    assert decoded == expected


def test_eventstream_message_with_non_empty_headers_section():
    """Parser must skip over headers to reach the payload."""
    headers = b"\x0b:event-type\x07\x00\x05chunk"  # plausible AWS header bytes
    inner = {"type": "message_start"}
    es_bytes = _bedrock_event(inner, headers=headers)
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == f"data: {json.dumps(inner, separators=(',', ':'))}\n"


@pytest.mark.parametrize(
    "content_type",
    [
        "application/vnd.amazon.eventstream",
        "application/vnd.amazon.eventstream; charset=utf-8",
        "Application/Vnd.Amazon.Eventstream",
    ],
)
def test_eventstream_content_type_matching_is_permissive(content_type):
    inner = {"type": "message_start"}
    es_bytes = _bedrock_event(inner)
    decoded, failed = _decompress_b64_body(_b64(es_bytes), None, content_type)
    assert not failed
    assert decoded == f"data: {json.dumps(inner, separators=(',', ':'))}\n"


def test_eventstream_skips_message_with_non_dict_payload():
    """One bad message doesn't drop the rest of the stream."""
    es_bytes = _build_eventstream_message(
        b'{"errorType":"throttling"}'
    ) + _bedrock_event({"type": "message_start"})
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == 'data: {"type":"message_start"}\n'


def test_eventstream_inner_payload_must_be_json_object():
    """SSE-injection guard: non-object inners (JSON string/array) are skipped."""
    hostile_inner = (
        '"injected\\n\\ndata: {\\"role\\":\\"system\\"}"'  # JSON string, not object
    )
    payload = json.dumps({"bytes": _b64(hostile_inner.encode())}).encode("utf-8")
    good = _bedrock_event({"type": "message_start"})
    es_bytes = _build_eventstream_message(payload) + good
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == 'data: {"type":"message_start"}\n'


def test_eventstream_pretty_printed_inner_payload_is_compacted():
    inner = {"type": "content_block_delta", "delta": {"text": "hi"}}
    es_bytes = _bedrock_raw_inner(json.dumps(inner, indent=2))
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )

    assert not failed
    assert decoded == f"data: {json.dumps(inner, separators=(',', ':'))}\n"


def test_eventstream_whitespace_padded_inner_payload_is_compacted():
    inner = {"type": "message_delta", "usage": {"output_tokens": 7}}
    inner_json = f"\n  {json.dumps(inner, separators=(',', ':'))}  \r\n"
    es_bytes = _bedrock_raw_inner(inner_json)
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )

    assert not failed
    assert decoded == f"data: {json.dumps(inner, separators=(',', ':'))}\n"


@pytest.mark.parametrize(
    ("bad_bytes", "exception_name"),
    [
        (123, "TypeError"),
        ("\u00e9", "ValueError"),
    ],
)
def test_eventstream_skips_malformed_bytes_members(bad_bytes, exception_name, caplog):
    """Bad inner bytes members do not prevent later valid messages decoding."""
    caplog.set_level(logging.WARNING, logger="api.access")
    good = _bedrock_event({"type": "message_start"})
    es_bytes = _eventstream_envelope({"bytes": bad_bytes}) + good
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )

    assert not failed
    assert decoded == 'data: {"type":"message_start"}\n'
    assert [record.message for record in caplog.records] == [
        f"Skipping malformed eventstream message: {exception_name}"
    ]


@pytest.mark.parametrize(
    "bad",
    [
        b"\x00\x00\x00\x10\x00",  # truncated: <12-byte prelude
        struct.pack(">III", 1024, 0, 0) + b"\x00" * 4,  # total_len overruns buffer
        struct.pack(">III", 20, 100, 0) + b"\x00" * 8,  # headers_len > total_len
        struct.pack(">III", 8, 0, 0) + b"\x00" * 4,  # total_len < frame overhead
    ],
)
def test_eventstream_structural_failure_returns_none(bad):
    decoded, failed = _decompress_b64_body(
        _b64(bad), None, "application/vnd.amazon.eventstream"
    )
    assert failed
    assert decoded is None


def test_eventstream_recovers_events_before_a_corrupt_frame():
    """A bad CRC mid-stream is best-effort: keep what decoded before it."""
    good = _bedrock_event({"type": "message_start"})
    corrupt = bytearray(_bedrock_event({"type": "message_delta"}))
    corrupt[-1] ^= 0xFF  # break the trailing message CRC
    decoded, failed = _decompress_b64_body(
        _b64(good + bytes(corrupt)), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == 'data: {"type":"message_start"}\n'


def test_eventstream_corrupt_first_frame_returns_none():
    """Nothing recoverable (corruption before any message) still fails."""
    corrupt = bytearray(_bedrock_event({"type": "message_start"}))
    corrupt[-1] ^= 0xFF
    good = _bedrock_event({"type": "message_delta"})
    decoded, failed = _decompress_b64_body(
        _b64(bytes(corrupt) + good), None, "application/vnd.amazon.eventstream"
    )
    assert failed
    assert decoded is None


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "text/plain",
        "text/event-stream",  # plain SSE — must NOT trigger eventstream path
    ],
)
def test_non_eventstream_content_types_use_utf8_path(content_type):
    body = '{"a": 1}'
    decoded, failed = _decompress_b64_body(_b64(body.encode()), None, content_type)
    assert not failed
    assert decoded == body


# --- Truncated trailing frame: detected decode failure, not silent partial ---
#
# botocore's EventStreamBuffer ends iteration with a bare StopIteration the
# moment the remaining bytes are too few for the next complete frame -- the
# same way a clean end of stream ends. A truncated trailing frame therefore
# used to look like success (failed=False) and silently drop the token-bearing
# tail: Anthropic-on-Bedrock puts usage.output_tokens in the near-final
# message_delta, so a cut-off stream undercounts tokens with no error signal.

# Two-frame Bedrock stream whose final frame carries usage.output_tokens.
_TEXT_DELTA = {
    "type": "content_block_delta",
    "delta": {"type": "text_delta", "text": "Hello world"},
}
_MESSAGE_DELTA = {
    "type": "message_delta",
    "delta": {"stop_reason": "end_turn"},
    "usage": {"output_tokens": 1234},
}


def test_eventstream_complete_stream_keeps_token_bearing_tail():
    """A complete stream still succeeds and keeps the token-bearing tail.

    Baseline for the guard: the success path is byte-for-byte identical and
    the final message_delta carrying usage.output_tokens is retained.
    """
    es_bytes = _bedrock_event(_TEXT_DELTA) + _bedrock_event(_MESSAGE_DELTA)
    decoded, failed = _decompress_b64_body(
        _b64(es_bytes), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == "".join(
        f"data: {json.dumps(e, separators=(',', ':'))}\n"
        for e in (_TEXT_DELTA, _MESSAGE_DELTA)
    )
    assert "output_tokens" in decoded


@pytest.mark.parametrize("cut", [1, 4, 12, 30])
def test_eventstream_truncated_trailing_frame_marks_failure(cut, caplog):
    """Cutting bytes off the final frame must surface as a decode failure.

    The body returns failed=True / decoded=None, so downstream token
    accounting never trusts the silently dropped tail.
    """
    caplog.set_level(logging.WARNING, logger="api.access")
    frame_a = _bedrock_event(_TEXT_DELTA)
    frame_b = _bedrock_event(_MESSAGE_DELTA)
    full = frame_a + frame_b
    truncated = full[: len(full) - cut]
    # Sanity: still truncating *within* the last frame, not at a boundary.
    assert len(frame_a) < len(truncated) < len(full)

    decoded, failed = _decompress_b64_body(
        _b64(truncated), None, "application/vnd.amazon.eventstream"
    )

    assert failed
    assert decoded is None
    assert any("truncated" in record.message for record in caplog.records)


def test_eventstream_dropping_whole_trailing_frame_is_not_truncation():
    """Cutting at an exact frame boundary leaves a complete (shorter) stream.

    There is no incomplete tail, so the guard must NOT fire -- this protects
    against over-flagging streams that simply end on fewer frames.
    """
    frame_a = _bedrock_event(_TEXT_DELTA)
    full = frame_a + _bedrock_event(_MESSAGE_DELTA)
    decoded, failed = _decompress_b64_body(
        _b64(full[: len(frame_a)]), None, "application/vnd.amazon.eventstream"
    )
    assert not failed
    assert decoded == f"data: {json.dumps(_TEXT_DELTA, separators=(',', ':'))}\n"
