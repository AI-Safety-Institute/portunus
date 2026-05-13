"""Behaviour tests for the ext_proc gRPC Process servicer.

Each test name reads as a claim about what the servicer guarantees.
``PublishService`` is replaced by a ``FakePublishService`` that records
every call's arguments — assertions inspect what was published, not how
many times a method was called.

End-to-end behaviour (real Kinesis, real Envoy, real WS clients) is
covered by the docker-compose-driven tests in ``tests/test_behaviours.py``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

import grpc
import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from google.protobuf import struct_pb2

from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.grpc.publish_queue import BoundedPublishQueue

# ---------------------------------------------------------------------------
# Fake publish service — records what was published so assertions can read
# the data flowing through, rather than counting internal method calls.
# ---------------------------------------------------------------------------


@dataclass
class _PublishedItem:
    """One thing the servicer asked Publish to send to Kinesis."""

    kind: str  # "request_headers" | "request_body" | "request_trailers" | ...
    request_id: str
    payload: dict = field(default_factory=dict)


class FakePublishService:
    """Captures every publish-* call. ``items`` is the ordered record of.

    everything the servicer dispatched.
    """

    def __init__(self) -> None:
        self.items: list[_PublishedItem] = []

    def _capture(self, kind: str):
        async def _impl(**kwargs):
            self.items.append(
                _PublishedItem(
                    kind=kind,
                    request_id=kwargs.get("request_id", ""),
                    payload={k: v for k, v in kwargs.items() if k != "request_id"},
                )
            )
            return True

        return _impl

    def __getattr__(self, name: str):
        if name.startswith("publish_"):
            return self._capture(name[len("publish_") :])
        raise AttributeError(name)

    # Helpers ----------------------------------------------------------------
    def kinds(self) -> list[str]:
        return [i.kind for i in self.items]

    def of_kind(self, kind: str) -> list[_PublishedItem]:
        return [i for i in self.items if i.kind == kind]


# ---------------------------------------------------------------------------
# Builders — protobuf scaffolding kept out of the test bodies
# ---------------------------------------------------------------------------


def _http_headers_message(
    *,
    headers: dict[str, str],
    is_request: bool,
    websocket_metadata: bool = False,
    request_id: Optional[str] = None,
) -> proc_pb2.ProcessingRequest:
    if request_id:
        headers = {**headers, "x-request-id": request_id}
    header_list = [base_pb2.HeaderValue(key=k, value=v) for k, v in headers.items()]
    headers_msg = proc_pb2.HttpHeaders(
        headers=base_pb2.HeaderMap(headers=header_list),
        end_of_stream=False,
    )
    kwargs: dict = (
        {"request_headers": headers_msg}
        if is_request
        else {"response_headers": headers_msg}
    )
    if websocket_metadata:
        kwargs["metadata_context"] = base_pb2.Metadata(
            filter_metadata={
                "envoy.filters.http.ext_proc": struct_pb2.Struct(
                    fields={"websocket": struct_pb2.Value(bool_value=True)}
                )
            }
        )
    return proc_pb2.ProcessingRequest(**kwargs)


def _http_body_message(*, body: bytes, is_request: bool) -> proc_pb2.ProcessingRequest:
    body_msg = proc_pb2.HttpBody(body=body, end_of_stream=False)
    if is_request:
        return proc_pb2.ProcessingRequest(request_body=body_msg)
    return proc_pb2.ProcessingRequest(response_body=body_msg)


async def _stream_from(items: list) -> AsyncIterator:
    for item in items:
        yield item


# ---------------------------------------------------------------------------
# Fake context — only what the servicer touches
# ---------------------------------------------------------------------------


class _FakeContext:
    def __init__(self, *, metadata: Optional[list[tuple[str, str]]] = None) -> None:
        self._metadata = list(metadata or [])
        self.aborted_with: Optional[tuple] = None

    def invocation_metadata(self) -> list[tuple[str, str]]:
        return self._metadata

    async def abort(self, code, details: str) -> None:
        self.aborted_with = (code, details)


_PROXY_KEY = "test-proxy-key-shhh"


def _ctx_with_key(value: Optional[str] = _PROXY_KEY) -> _FakeContext:
    metadata = [("x-portunus-proxy-key", value)] if value is not None else []
    return _FakeContext(metadata=metadata)


@pytest.fixture(autouse=True)
def _enable_proxy_key_validation(monkeypatch):
    from portunus.config import config as portunus_config

    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", _PROXY_KEY)


def _make_servicer(
    *, queue_maxsize: int = 10_000, publish: Optional[FakePublishService] = None
) -> tuple[PortunusProcessServicer, FakePublishService, BoundedPublishQueue]:
    publish = publish or FakePublishService()
    queue = BoundedPublishQueue(maxsize=queue_maxsize, num_workers=2)
    servicer = PortunusProcessServicer(publish_service=publish, publish_queue=queue)
    return servicer, publish, queue


async def _drain_queue(queue: BoundedPublishQueue, *, timeout: float = 1.0) -> None:
    """Wait for the queue to fully drain so publish-side assertions see all.

    items the servicer dispatched. Avoids a fixed ``sleep(0.1)`` that
    relies on workers being faster than wall-clock.
    """
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        if queue.qsize() == 0:
            # Give workers one more event-loop tick to finish their task.
            await asyncio.sleep(0)
            if queue.qsize() == 0:
                return
        await asyncio.sleep(0.01)
    raise AssertionError("publish queue did not drain within timeout")


# ---------------------------------------------------------------------------
# HTTP path — request and response halves
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_request_headers_are_published_with_their_headers_intact():
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={"x-foo": "bar"},
                    is_request=True,
                    request_id="req-123",
                )
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        import base64

        request_headers = publish.of_kind("request_headers")
        assert len(request_headers) == 1
        assert request_headers[0].request_id == "req-123"
        # Wire format is base64-encoded for aisitok compatibility — see
        # _headers_to_dict in proc_servicer.
        encoded = request_headers[0].payload["headers"]["x-foo"]
        assert base64.b64decode(encoded).decode() == "bar"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_http_response_body_chunks_are_published_with_their_bytes_intact():
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="req-x"),
                _http_body_message(body=b"hello world", is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        response_bodies = publish.of_kind("response_body")
        assert len(response_bodies) == 1
        assert response_bodies[0].payload["body_bytes"] == b"hello world"
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# WS detection — driven by the filter metadata Envoy attaches. Tested via
# the observable side effect (a WS-mode stream parses frames) rather than
# by calling the private ``_extract_mode`` directly.
# ---------------------------------------------------------------------------


def _ws_frame(payload: bytes) -> bytes:
    """Single-fragment, unmasked WS text frame with the given payload."""
    header = bytes([0x81, len(payload)])  # FIN | text opcode, payload length
    return header + payload


@pytest.mark.asyncio
async def test_websocket_stream_publishes_decoded_message_text_not_raw_frame_bytes():
    """A WS-tagged stream means the servicer should parse frames via.

    wsproto and publish the decoded message payload. If the metadata flag
    were ignored the publish would carry raw frame bytes (header + body).
    Observing the decoded payload confirms the WS path is in effect.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-1",
                ),
                _http_body_message(body=_ws_frame(b"hello"), is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        # The body publish should be the decoded "hello", not the framed bytes.
        body_items = publish.of_kind("response_body")
        decoded = [i.payload.get("body_bytes") for i in body_items]
        assert any(
            b == b"hello" for b in decoded
        ), f"Expected decoded 'hello'; got {decoded!r}"
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Bounded queue drop policy — under back-pressure, drop body chunks rather
# than blocking the customer's request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_chunks_are_dropped_when_queue_is_full_and_increment_drop_counter():
    """Tiny queue + no workers running → put_nowait will fail past.

    capacity, the servicer should swallow those bodies and bump the drop
    counter. The customer's request must still receive its per-message
    Envoy response.
    """
    servicer, _publish, queue = _make_servicer(queue_maxsize=2)
    # NB: workers deliberately not started so the queue stays full.

    stream = _stream_from(
        [
            _http_headers_message(headers={}, is_request=True, request_id="drop-test"),
            _http_body_message(body=b"a" * 100, is_request=False),
            _http_body_message(body=b"b" * 100, is_request=False),
            _http_body_message(body=b"c" * 100, is_request=False),
            _http_body_message(body=b"d" * 100, is_request=False),
        ]
    )

    responses = [r async for r in servicer.Process(stream, _ctx_with_key())]

    # The customer-facing contract: every ProcessingRequest gets a
    # ProcessingResponse, regardless of whether the body was dropped.
    assert len(responses) == 5
    # And at least one drop must have been counted.
    assert queue.dropped_total >= 1


# ---------------------------------------------------------------------------
# Drain protocol — active WS streams receive a 1012 close frame
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drain_injects_ws_close_frame_with_code_1012_on_active_ws_stream():
    """When the servicer is asked to drain, every active WS stream gets a.

    close frame injected into its response so clients learn the server is
    going away. We observe the close frame bytes on the second response.
    """
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        ready = asyncio.Event()
        drain_done = asyncio.Event()

        async def iterator() -> AsyncIterator:
            yield _http_headers_message(
                headers={},
                is_request=True,
                websocket_metadata=True,
                request_id="drain-1",
            )
            ready.set()
            await drain_done.wait()
            yield _http_body_message(body=b"another frame", is_request=False)

        async def driver() -> list:
            return [r async for r in servicer.Process(iterator(), _ctx_with_key())]

        task = asyncio.create_task(driver())
        await ready.wait()
        await servicer.drain_all()
        drain_done.set()
        results = await asyncio.wait_for(task, timeout=2.0)

        assert len(results) == 2
        body = results[1].response_body.response.body_mutation.streamed_response.body
        # WS close frame: 0x88 = FIN|close opcode; then 2-byte big-endian code.
        assert body[0] == 0x88
        assert int.from_bytes(body[2:4], "big") == 1012
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Proxy-key identity check — once per stream at stream open
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_proxy_key_aborts_the_stream_before_yielding_any_response():
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [_http_headers_message(headers={}, is_request=True, request_id="no-key")]
        )
        ctx = _ctx_with_key(value=None)

        responses = [r async for r in servicer.Process(stream, ctx)]

        assert responses == []
        assert ctx.aborted_with is not None
        code, detail = ctx.aborted_with
        assert code == grpc.StatusCode.PERMISSION_DENIED
        assert "proxy identity" in detail.lower()
        # And — no publish should have leaked through for a stream that
        # never proved its identity.
        assert publish.items == []
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_wrong_proxy_key_aborts_the_stream_before_yielding_any_response():
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [_http_headers_message(headers={}, is_request=True, request_id="wrong")]
        )
        ctx = _ctx_with_key(value="wrong-key")

        responses = [r async for r in servicer.Process(stream, ctx)]

        assert responses == []
        assert ctx.aborted_with[0] == grpc.StatusCode.PERMISSION_DENIED
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Envoy 1.36 FDS contract — body responses must wrap in streamed_response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_response_uses_streamed_response_envelope_required_by_envoy():
    """Envoy 1.36 in FULL_DUPLEX_STREAMED mode rejects a plain.

    CommonResponse on body messages — the body_mutation must wrap a
    streamed_response (even when empty). Regression test against
    reverting the envelope.
    """
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="shape"),
                _http_body_message(body=b"body", is_request=True),
            ]
        )

        responses = [r async for r in servicer.Process(stream, _ctx_with_key())]

        body_response = responses[1].request_body
        assert body_response.response.body_mutation.HasField("streamed_response")
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# WS summary record — emitted once per upgraded connection at stream end
# ---------------------------------------------------------------------------


def _ws_client_text_frame(payload: bytes) -> bytes:
    """Masked text frame from client → server.

    RFC 6455 §5.3 requires the MASK bit set and a 4-byte masking key for
    all client-originated frames. wsproto's SERVER-role Connection rejects
    unmasked client frames as a protocol violation.
    """
    mask_key = b"\x00\x00\x00\x00"  # all-zero mask → payload bytes unchanged
    return (
        bytes([0x81, 0x80 | len(payload)])  # FIN | text opcode, MASK | length
        + mask_key
        + bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    )


def _ws_server_close_frame(code: int) -> bytes:
    """Unmasked close frame from server → client carrying a status code."""
    payload = code.to_bytes(2, "big")
    return bytes([0x88, len(payload)]) + payload


@pytest.mark.asyncio
async def test_ws_stream_emits_a_summary_with_frame_counts_and_close_code():
    """At stream finalisation, an upgraded WS connection should produce.

    exactly one summary record carrying directional frame counts and the
    observed close code. The summary is what analytics queries reach for
    instead of aggregating body records.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-summary-1",
                ),
                _http_body_message(
                    body=_ws_client_text_frame(b"ping-from-client"),
                    is_request=True,
                ),
                _http_body_message(
                    body=_ws_frame(b"first-server-frame"), is_request=False
                ),
                _http_body_message(
                    body=_ws_frame(b"second-server-frame"), is_request=False
                ),
                _http_body_message(
                    body=_ws_server_close_frame(1000), is_request=False
                ),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        summaries = publish.of_kind("ws_summary")
        assert len(summaries) == 1, f"Expected one summary, got {summaries}"
        record = summaries[0].payload["record"]
        assert record.request_id == "ws-summary-1"
        assert record.client_text_frames == 1
        assert record.server_text_frames == 2
        assert record.server_close_frames == 1
        assert record.close_code == 1000
        assert record.close_initiator == "server"
        assert record.duration_seconds >= 0.0
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_ws_summary_close_initiator_is_client_when_client_sends_close():
    """A close frame from the client side should be attributed correctly."""
    # RFC 6455 §5.5.1 close frame: opcode 0x8, masked from client, payload =
    # 2-byte big-endian status code (optionally + reason).
    mask_key = b"\x00\x00\x00\x00"
    payload = (1001).to_bytes(2, "big")
    client_close = (
        bytes([0x88, 0x80 | len(payload)])
        + mask_key
        + bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    )

    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-client-close",
                ),
                _http_body_message(body=client_close, is_request=True),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        record = publish.of_kind("ws_summary")[0].payload["record"]
        assert record.client_close_frames == 1
        assert record.close_code == 1001
        assert record.close_initiator == "client"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_http_stream_does_not_emit_a_ws_summary():
    """Plain HTTP streams must not produce ws_summary records — the.

    summary is connection-shaped and only meaningful for upgraded WS.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="http-1"),
                _http_body_message(body=b"hello", is_request=True),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        assert publish.of_kind("ws_summary") == []
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_ws_summary_close_code_is_none_when_no_close_frame_observed():
    """If a WS stream ends without a close frame (e.g. TCP reset, drain).

    the summary should still publish, but with ``close_code = None`` so
    analytics can distinguish clean closes from abrupt drops.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-no-close",
                ),
                _http_body_message(body=_ws_frame(b"only-message"), is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        record = publish.of_kind("ws_summary")[0].payload["record"]
        assert record.close_code is None
        assert record.close_initiator is None
        assert record.server_text_frames == 1
    finally:
        await queue.stop()
