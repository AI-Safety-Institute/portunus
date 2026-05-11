"""Tests for ``_decompress_b64_body``: plain, gzip/deflate, eventstream."""

import base64
import gzip
import json
import struct
import zlib

import pytest

from portunus.models import (
    _decompress_b64_body,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _build_eventstream_message(payload: bytes, headers: bytes = b"") -> bytes:
    """[12-byte prelude][headers][payload][4-byte CRC]; CRCs zeroed."""
    total_len = 12 + len(headers) + len(payload) + 4
    prelude = struct.pack(">III", total_len, len(headers), 0)
    return prelude + headers + payload + struct.pack(">I", 0)


def _bedrock_event(inner_obj: dict, headers: bytes = b"") -> bytes:
    """One eventstream message wrapping an Anthropic-shaped inner event."""
    inner_json = json.dumps(inner_obj, separators=(",", ":"))
    payload = json.dumps({"bytes": _b64(inner_json.encode("utf-8"))}).encode("utf-8")
    return _build_eventstream_message(payload, headers)


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
