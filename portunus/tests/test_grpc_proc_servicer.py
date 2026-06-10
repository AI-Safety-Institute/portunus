"""Behaviour tests for the ext_proc gRPC Process servicer.

Each test name reads as a claim about what the servicer guarantees.
``PublishService`` is replaced by a ``FakePublishService`` that records
every call's arguments — assertions inspect what was published, not how
many times a method was called.

End-to-end behaviour (real Firehose, real Envoy, real WS clients) is
covered by the docker-compose-driven tests in ``tests/test_http_proxy_behaviour.py``
and ``tests/test_ws_proxy_behaviour.py``.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

import grpc
import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from google.protobuf import struct_pb2

from portunus.config import config as portunus_config
from portunus.grpc.frame_observer import Direction
from portunus.grpc.proc_servicer import (
    _PRE_101_MAX_BYTES,
    PortunusProcessServicer,
    StreamMode,
    _header_value,
    _header_value_bytes,
    _headers_to_dict,
    _StreamState,
)
from portunus.services.publish_queue import BoundedPublishQueue

# ---------------------------------------------------------------------------
# Fake publish service — records what was published so assertions can read
# the data flowing through, rather than counting internal method calls.
# ---------------------------------------------------------------------------


@dataclass
class _PublishedItem:
    """One thing the servicer asked Publish to send to Firehose."""

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


def _http_body_message(
    *, body: bytes, is_request: bool, end_of_stream: bool = False
) -> proc_pb2.ProcessingRequest:
    body_msg = proc_pb2.HttpBody(body=body, end_of_stream=end_of_stream)
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
    # monkeypatch: proxy_api_key lives in a module-level Pydantic config
    # singleton (see config.py); the gRPC servicers read it directly,
    # so constructor injection wouldn't reach the validation call site.
    monkeypatch.setattr(portunus_config.grpc, "proxy_api_key", _PROXY_KEY)


def _make_servicer(
    *, queue_maxsize: int = 10_000, publish: Optional[FakePublishService] = None
) -> tuple[PortunusProcessServicer, FakePublishService, BoundedPublishQueue]:
    publish = publish or FakePublishService()
    queue = BoundedPublishQueue(maxsize=queue_maxsize, num_workers=2)
    servicer = PortunusProcessServicer(
        publish_service=publish,  # type: ignore[arg-type]
        publish_queue=queue,
    )
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
async def test_headers_are_read_from_raw_value_field_when_value_is_empty():
    """Envoy 1.20+ populates HeaderValue.raw_value (bytes) and leaves the.

    deprecated ``value`` string empty. Reading only ``value`` returns
    ``""`` and an empty x-request-id loses join-key correlation across
    audit records. Build a HeaderMap that only sets raw_value and
    confirm the servicer reads it correctly.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        header_list = [
            base_pb2.HeaderValue(key="x-request-id", raw_value=b"req-from-raw"),
            base_pb2.HeaderValue(key="x-foo", raw_value=b"bar"),
        ]
        headers_msg = proc_pb2.HttpHeaders(
            headers=base_pb2.HeaderMap(headers=header_list),
            end_of_stream=False,
        )
        stream = _stream_from([proc_pb2.ProcessingRequest(request_headers=headers_msg)])

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        published = publish.of_kind("request_headers")
        assert len(published) == 1
        assert published[0].request_id == "req-from-raw"
        encoded = published[0].payload["headers"]["x-foo"]
        assert base64.b64decode(encoded).decode() == "bar"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_credential_headers_are_redacted_from_published_request_headers():
    """Strip credential-carrying headers before publishing audit records.

    ext_proc observes headers AFTER ext_authz rewrites ``Authorization`` to
    the real upstream provider API key. Publishing that verbatim would
    archive customer secrets to Firehose. Mirrors the legacy Lua filter's
    exclusion. Also strips ``x-api-key`` (Anthropic-style key location),
    ``cookie`` / ``set-cookie`` (session credentials), ``proxy-authorization``
    (forward-proxy bearer tokens), and ``x-amz-security-token`` (STS session
    tokens forwarded by clients that signed requests upstream of us).
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={
                        "authorization": "Bearer sk-ant-real-provider-key",
                        "x-api-key": "sk-real",
                        "cookie": "session=secret-session",
                        "proxy-authorization": "Basic dXNlcjpwYXNz",
                        "x-amz-security-token": "FQoGZX...EXAMPLE",
                        "x-foo": "bar",
                    },
                    is_request=True,
                    request_id="req-redact",
                )
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        request_headers = publish.of_kind("request_headers")
        assert len(request_headers) == 1
        published = request_headers[0].payload["headers"]
        assert "authorization" not in published
        assert "x-api-key" not in published
        assert "cookie" not in published
        assert "proxy-authorization" not in published
        assert "x-amz-security-token" not in published
        # Non-sensitive headers are preserved.
        encoded = published["x-foo"]
        assert base64.b64decode(encoded).decode() == "bar"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_credential_headers_are_redacted_from_published_response_headers():
    """Redaction also applies to the response side.

    Upstreams set ``Set-Cookie`` (and can echo any of the request-side
    credential headers) — we must not archive those to Firehose verbatim.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={}, is_request=True, request_id="req-resp-redact"
                ),
                _http_headers_message(
                    headers={
                        "set-cookie": "session=secret-session; HttpOnly",
                        "authorization": "Bearer leftover",
                        "x-api-key": "sk-leak",
                        "cookie": "tracker=xyz",
                        "proxy-authorization": "Basic dXNlcjpwYXNz",
                        "x-amz-security-token": "FQoGZX...EXAMPLE",
                        "x-foo": "bar",
                    },
                    is_request=False,
                ),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        response_headers = publish.of_kind("response_headers")
        assert len(response_headers) == 1
        published = response_headers[0].payload["headers"]
        assert "set-cookie" not in published
        assert "authorization" not in published
        assert "x-api-key" not in published
        assert "cookie" not in published
        assert "proxy-authorization" not in published
        assert "x-amz-security-token" not in published
        encoded = published["x-foo"]
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
# WS-frame helper. ext_proc does not observe post-101 frames; the invariant
# below asserts that if such bytes did arrive, they aren't frame-decoded.
# ---------------------------------------------------------------------------


def _ws_frame(payload: bytes) -> bytes:
    """Single-fragment, unmasked WS text frame with the given payload."""
    header = bytes([0x81, len(payload)])  # FIN | text opcode, payload length
    return header + payload


def test_pre_101_buffer_overflow_poisons_stream_instead_of_truncating(caplog):
    """An over-cap pre-101 chunk poisons the stream rather than truncating.

    Truncating raw WS bytes mid-frame would desync the frame parser + zlib
    state on replay, silently corrupting every later frame. Poisoning instead
    skips observation and records the loss via the truncated counter.
    """
    servicer, _publish, _queue = _make_servicer()
    state = _StreamState(
        stream_id="stream-pre-101",
        request_id="req-pre-101",
        mode=StreamMode.WS_UPGRADE,
    )
    chunk = b"x" * (_PRE_101_MAX_BYTES + 17)

    with caplog.at_level(logging.WARNING, logger="api.access"):
        servicer._buffer_pre_101(state, Direction.REQUEST, chunk)

    # Poisoned, not truncated: buffer cleared, nothing replayable, loss counted.
    assert state.pre_101_poisoned is True
    assert state.pre_101_buffer == []
    assert state.pre_101_bytes == 0
    assert state.truncated_client_frames == 1
    assert any("poisoning stream" in record.getMessage() for record in caplog.records)


def test_pre_101_poisoned_stream_skips_replay_and_observation():
    """Once poisoned, replay is a no-op and further pre-101 chunks are ignored."""
    servicer, _publish, _queue = _make_servicer()
    state = _StreamState(
        stream_id="stream-pre-101-poison",
        request_id="req-pre-101-poison",
        mode=StreamMode.WS_UPGRADE,
    )
    servicer._buffer_pre_101(state, Direction.REQUEST, b"x" * (_PRE_101_MAX_BYTES + 1))
    assert state.pre_101_poisoned is True

    # Replay must not raise or emit anything (buffer already cleared).
    servicer._replay_pre_101(state, "2026-01-01T00:00:00Z")
    # A subsequent under-cap chunk must still be ignored (no re-buffering).
    servicer._buffer_pre_101(state, Direction.REQUEST, b"small")
    assert state.pre_101_buffer == []


# ---------------------------------------------------------------------------
# Bounded queue drop policy — under back-pressure, drop body chunks rather
# than blocking the customer's request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_chunks_are_dropped_when_publish_queue_is_full():
    """With per-chunk publishing, body submits use ``put_nowait`` and.

    drop when capacity is exceeded — exactly so a slow Firehose can't
    backpressure customer traffic. Tiny queue + no workers + a few
    body chunks → drop_total increments.

    Under ``observability_mode: true`` body events do not yield a
    ProcessingResponse (Envoy ignores them); only the request_headers
    event does. Drops continue to happen on the publish queue.
    """
    servicer, _publish, queue = _make_servicer(queue_maxsize=2)
    # Workers deliberately not started so the queue stays full.

    stream = _stream_from(
        [
            _http_headers_message(headers={}, is_request=True, request_id="drop-test"),
            _http_body_message(body=b"a" * 100, is_request=False),
            _http_body_message(body=b"b" * 100, is_request=False),
            _http_body_message(body=b"c" * 100, is_request=False),
            _http_body_message(body=b"d" * 100, is_request=False, end_of_stream=True),
        ]
    )

    responses = [r async for r in servicer.Process(stream, _ctx_with_key())]

    # Headers event yields one response; body events do not under
    # observability_mode. Drops still register against the publish queue.
    assert len(responses) == 1
    assert queue.dropped_total >= 1


@pytest.mark.asyncio
async def test_body_drop_emits_dropped_sentinel_record():
    """When a body chunk is dropped under queue pressure, a sentinel.

    record with ``dropped=True`` and empty body is enqueued so downstream
    ETL sees an explicit gap marker rather than a silent chunk_id
    discontinuity. The fallback signal (chunk_id gap) still exists; this
    is an explicit ``dropped=True`` row keyed to the lost chunk_id.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        # Two response body chunks; force-drop the second by saturating
        # the queue between submits. Easier to assert in isolation than
        # in the saturation test, which intentionally has no workers.
        captured: list[bool] = []

        original_submit = queue.submit_droppable

        def _fake_submit(task):
            # First call (the real chunk) succeeds; second (sentinel) too.
            # Middle call (the next real chunk) is forced to drop.
            label = task.label
            if "drop_sentinel" in label:
                return original_submit(task)
            accepted = len(captured) % 2 == 0
            captured.append(accepted)
            if accepted:
                return original_submit(task)
            queue._dropped_total += 1
            return False

        queue.submit_droppable = _fake_submit  # type: ignore[assignment]

        stream = _stream_from(
            [
                _http_headers_message(
                    headers={}, is_request=True, request_id="sentinel-test"
                ),
                _http_body_message(body=b"first", is_request=False),
                _http_body_message(body=b"second", is_request=False),
            ]
        )
        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("response_body")
        # One real chunk + one drop sentinel. The dropped chunk itself
        # does not produce a record (it's the *real* record that was
        # rejected); the sentinel takes its place keyed to the same
        # chunk_id.
        real = [b for b in bodies if not b.payload.get("dropped")]
        sentinels = [b for b in bodies if b.payload.get("dropped")]
        assert len(real) == 1
        assert real[0].payload["body_bytes"] == b"first"
        assert len(sentinels) == 1
        assert sentinels[0].payload["body_bytes"] == b""
        assert sentinels[0].payload["chunk_id"] == 1  # second chunk's id
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
# Envoy 1.36 FDS contract — every body chunk gets a streamed_response;
# the terminal chunk mirrors end_of_stream so Envoy unblocks the HCM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_events_yield_no_processing_response_under_observability_mode():
    """envoy.yaml sets ``observability_mode: true``, so Envoy ignores any.

    ProcessingResponse the servicer yields. Pin the contract:
    header events yield one response, body events yield nothing —
    no wasted protobuf allocation or gRPC send per chunk.
    """
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="shape"),
                _http_body_message(body=b"first", is_request=True),
                _http_body_message(body=b"last", is_request=True, end_of_stream=True),
            ]
        )

        responses = [r async for r in servicer.Process(stream, _ctx_with_key())]

        # request_headers yields one response. Both body events yield
        # nothing (Envoy ignores body responses in observability_mode).
        assert len(responses) == 1
        assert responses[0].HasField("request_headers")
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_headers_response_uses_headers_field_not_body_field():
    """Yielding ``request_body=BodyResponse(...)`` for a request_headers.

    message generates "Spurious response message 3" in Envoy and fails
    the filter with a 500. The response for a headers message must use
    the matching ``request_headers`` / ``response_headers`` oneof field
    carrying a ``HeadersResponse``.
    """
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="shape"),
            ]
        )

        responses = [r async for r in servicer.Process(stream, _ctx_with_key())]

        assert len(responses) == 1
        assert responses[0].HasField("request_headers")
        assert not responses[0].HasField("request_body")
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Body chunking — each ext_proc body message lands as one Firehose record
# with a monotonic chunk_id and ``num_chunks=0`` (sentinel). The akp Glue
# job (process_raw_data.reassemble_body_chunks) aggregates these into one
# body record per request_id in the joined-log output that aisitok reads.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_streamed_body_chunks_have_monotonic_ids_and_sentinel_num_chunks():
    """Each ext_proc response_body message becomes its own Firehose record.

    with a sequential ``chunk_id`` per direction and ``num_chunks=0``.
    The Glue ETL groups by request_id, sorts by chunk_id, and
    concatenates body bytes — so we hold no body state on the
    portunus side and streaming responses (Anthropic / OpenAI SSE)
    reach Firehose as they arrive instead of being buffered to EOS.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="sse-1"),
                _http_body_message(body=b"chunk-a", is_request=False),
                _http_body_message(body=b"chunk-b", is_request=False),
                _http_body_message(
                    body=b"chunk-c", is_request=False, end_of_stream=True
                ),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("response_body")
        ids = [b.payload["chunk_id"] for b in bodies]
        nums = [b.payload["num_chunks"] for b in bodies]
        body_bytes = [b.payload["body_bytes"] for b in bodies]
        assert ids == [0, 1, 2]
        assert nums == [0, 0, 0]
        assert body_bytes == [b"chunk-a", b"chunk-b", b"chunk-c"]
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_large_body_message_is_split_into_monotonic_body_records():
    servicer, publish, queue = _make_servicer()
    body = b"x" * (2 * 1024 * 1024 + 123)
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="big-1"),
                _http_body_message(body=body, is_request=True, end_of_stream=True),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("request_body")
        assert len(bodies) > 1
        assert [b.payload["chunk_id"] for b in bodies] == list(range(len(bodies)))
        assert [b.payload["num_chunks"] for b in bodies] == [0] * len(bodies)
        assert b"".join(b.payload["body_bytes"] for b in bodies) == body
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_request_and_response_chunk_ids_are_independent_per_direction():
    """Request-side and response-side ``chunk_id`` counters are separate so a.

    request-body chunk and a response-body chunk can both legitimately
    be ``chunk_id=0`` — they're disambiguated by direction (which is
    the stream the record is published to).
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={}, is_request=True, request_id="bidir-1"
                ),
                _http_body_message(body=b"req-0", is_request=True),
                _http_body_message(body=b"req-1", is_request=True, end_of_stream=True),
                _http_body_message(body=b"resp-0", is_request=False),
                _http_body_message(
                    body=b"resp-1", is_request=False, end_of_stream=True
                ),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        req_ids = [b.payload["chunk_id"] for b in publish.of_kind("request_body")]
        resp_ids = [b.payload["chunk_id"] for b in publish.of_kind("response_body")]
        assert req_ids == [0, 1]
        assert resp_ids == [0, 1]
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_aborted_stream_emits_records_for_chunks_seen_so_far():
    """If the stream ends without an ``end_of_stream=true`` chunk (client.

    disconnect, upstream reset), every chunk that did arrive is already
    published — there's no portunus-side buffer to lose. Glue's
    aggregation will produce a partial-body joined-log record from the
    chunks present.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="abrupt"),
                _http_body_message(body=b"partial-", is_request=False),
                _http_body_message(body=b"body", is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("response_body")
        assert [b.payload["body_bytes"] for b in bodies] == [b"partial-", b"body"]
        assert [b.payload["chunk_id"] for b in bodies] == [0, 1]
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Active-stream registry — keyed by internal stream id, not x-request-id
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_streams_with_same_request_id_register_independently():
    """Two concurrent streams that share an x-request-id must register.

    independently. Envoy preserves a client-supplied ``x-request-id`` in
    some trust configurations; keying the active-stream registry by
    request_id would let stream B's registration overwrite stream A's,
    losing its summary record on close. Keying by an internal stream_id
    fixes this — both streams stay in the registry.
    """
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        ready_a = asyncio.Event()
        ready_b = asyncio.Event()
        hold_a = asyncio.Event()
        hold_b = asyncio.Event()
        shared_request_id = "collision-id"

        async def iterator(ready, hold):
            yield _http_headers_message(
                headers={},
                is_request=True,
                request_id=shared_request_id,
            )
            ready.set()
            await hold.wait()

        async def driver(it):
            return [r async for r in servicer.Process(it, _ctx_with_key())]

        task_a = asyncio.create_task(driver(iterator(ready_a, hold_a)))
        task_b = asyncio.create_task(driver(iterator(ready_b, hold_b)))
        await ready_a.wait()
        await ready_b.wait()

        # Both streams should be in the active registry under distinct
        # internal stream_ids despite sharing a request_id.
        assert servicer.active_stream_count == 2
        stream_ids = list(servicer._active.keys())
        assert len(set(stream_ids)) == 2

        hold_a.set()
        hold_b.set()
        await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=2.0)
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# _header_value{,_bytes}: lossless byte handling and divergence detection
# ---------------------------------------------------------------------------


def test_header_value_bytes_returns_raw_value_when_only_that_field_set():
    """Modern Envoy: only ``raw_value`` is populated; ``value`` is empty."""
    h = base_pb2.HeaderValue(key="x-foo", raw_value=b"\xc3\xa9clair")  # éclair
    assert _header_value_bytes(h) == b"\xc3\xa9clair"


def test_header_value_bytes_falls_back_to_value_when_only_legacy_field_set():
    """Older Envoy: only ``value`` is populated; ``raw_value`` is empty."""
    h = base_pb2.HeaderValue(key="x-foo", value="legacy-only")
    assert _header_value_bytes(h) == b"legacy-only"


def test_header_value_bytes_preserves_non_utf8_bytes_through_to_publish(caplog):
    """Binary header values (e.g. Sec-WebSocket-Key) must survive raw.

    Bytes pass through to base64 without UTF-8 decoding, so downstream
    consumers can recover the original payload exactly.
    """
    raw = bytes(range(256))  # every byte 0x00..0xff
    h = base_pb2.HeaderValue(key="x-binary", raw_value=raw)
    assert _header_value_bytes(h) == raw

    header_map = base_pb2.HeaderMap(headers=[h])
    encoded = _headers_to_dict(header_map)["x-binary"]
    assert base64.b64decode(encoded) == raw


def test_header_value_bytes_warns_when_raw_and_legacy_diverge(caplog):
    """A non-conforming Envoy that sets both fields differently is forensic.

    Log a warning so an operator can correlate the divergence with an
    unexpected proxy build, rather than silently preferring ``raw_value``
    and losing the fact that ``value`` was different.
    """
    h = base_pb2.HeaderValue(
        key="x-strange",
        raw_value=b"from-raw",
        value="from-legacy",
    )

    with caplog.at_level(logging.WARNING, logger="portunus.grpc.proc_servicer"):
        result = _header_value_bytes(h)

    assert result == b"from-raw"  # raw_value wins
    assert any("divergence" in r.getMessage() for r in caplog.records)


def test_header_value_str_remains_lossy_for_free_text_callers():
    """``_header_value`` is the convenience str view; non-UTF-8 → U+FFFD.

    Callers that read string identifiers (e.g. ``_extract_request_id``)
    are happy with replacement-on-garbage. The lossless path is
    ``_header_value_bytes`` + base64 for publish.
    """
    h = base_pb2.HeaderValue(key="x-bin", raw_value=b"\xff\xfe\xfd")
    decoded = _header_value(h)
    assert "�" in decoded


# ---------------------------------------------------------------------------
# WS frame observation — Envoy 1.36 ext_proc delivers post-101 body bytes in
# both directions under FULL_DUPLEX_STREAMED. The servicer parses each WS
# frame, publishes per-frame body records, and emits one summary record per
# connection.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_tagged_stream_emits_frame_and_summary_records():
    """A WS-tagged ext_proc stream observes post-upgrade frames and emits a summary."""
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-stream-1",
                ),
                _http_headers_message(headers={}, is_request=False),
                # Server-side WS text frame — must be parsed by FrameObserver
                # and emitted as a response_body record with the frame payload.
                _http_body_message(body=_ws_frame(b"hello"), is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        # One response_body record carrying the decoded frame payload.
        resp_body_items = publish.of_kind("response_body")
        assert any(
            item.payload.get("body_bytes") == b"hello" for item in resp_body_items
        ), f"expected decoded frame payload, got {resp_body_items}"
        # A summary record on stream close.
        summaries = publish.of_kind("ws_summary")
        assert len(summaries) == 1, summaries
        record = summaries[0].payload["record"]
        assert record.request_id == "ws-stream-1"
        assert record.server_text_frames == 1
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_ws_summary_uses_blocking_submit_on_normal_close():
    """The summary is the backstop for dropped frame counters."""
    servicer, publish, queue = _make_servicer()
    blocking_labels: list[str] = []
    droppable_labels: list[str] = []
    original_blocking = queue.submit_blocking
    original_droppable = queue.submit_droppable

    async def _capture_blocking(task):
        blocking_labels.append(task.label)
        await original_blocking(task)

    def _capture_droppable(task):
        droppable_labels.append(task.label)
        return original_droppable(task)

    queue.submit_blocking = _capture_blocking  # type: ignore[method-assign]
    queue.submit_droppable = _capture_droppable  # type: ignore[method-assign]

    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-summary-blocking",
                ),
                _http_headers_message(headers={}, is_request=False),
                _http_body_message(body=_ws_frame(b"hello"), is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        assert "ws_summary" in blocking_labels
        assert "ws_summary" not in droppable_labels
        assert len(publish.of_kind("ws_summary")) == 1
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# x-portunus-debug-id propagation — the load-test integrity checker scans
# ``raw_headers["x-portunus-debug-id"]`` on portunus-stream-request-headers
# to correlate a synthetic client-side debug id with the Envoy-assigned
# request_id. The servicer must surface the header verbatim (base64-encoded
# bytes) for every ext_proc stream shape — HTTP nosig, HTTP with the
# signing-pass mutations already applied by ext_authz #2, and WS upgrade GET.
# Envoy strips ``x-portunus-debug-id`` at ``request_headers_to_remove`` time
# (route_config in proxy/envoy.yaml) so it never reaches upstream, but that
# happens in the router (terminal) filter — ext_proc reads decodeHeaders
# strictly before the router and is the audit trail's only chance to capture
# the value.
# ---------------------------------------------------------------------------


def _decoded_header(headers_dict: dict[str, str], key: str) -> str:
    return base64.b64decode(headers_dict[key]).decode()


@pytest.mark.asyncio
async def test_http_nosig_request_headers_carry_x_portunus_debug_id():
    """Baseline: plain HTTP request carries the debug id into raw_headers."""
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={"x-portunus-debug-id": "DEBUG-A"},
                    is_request=True,
                    request_id="req-nosig",
                )
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        published = publish.of_kind("request_headers")
        assert len(published) == 1
        assert published[0].request_id == "req-nosig"
        assert (
            _decoded_header(published[0].payload["headers"], "x-portunus-debug-id")
            == "DEBUG-A"
        )
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_signing_pass_request_headers_carry_x_portunus_debug_id():
    """Signing-pass: ext_authz #2 has already mutated headers (content-digest,.

    signature, signature-input, x-portunus-signing-required) by the time
    decodeHeaders reaches ext_proc. The debug id sits alongside those
    mutations and must survive into raw_headers — the integrity checker
    can't correlate without it.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={
                        "x-portunus-debug-id": "DEBUG-B",
                        "x-portunus-signing-required": "true",
                        "content-digest": "sha-256=:aGVsbG8=:",
                        "signature": "sig1=:Zm9vYmFy:",
                        "signature-input": (
                            'sig1=("@method" "@target-uri" "content-digest" '
                            '"content-type" "x-api-key");created=1762970351;'
                            'keyid="signingkey_12345";alg="ecdsa-p256-sha256"'
                        ),
                        "content-type": "application/json",
                    },
                    is_request=True,
                    request_id="req-signing",
                )
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        published = publish.of_kind("request_headers")
        assert len(published) == 1
        raw = published[0].payload["headers"]
        assert _decoded_header(raw, "x-portunus-debug-id") == "DEBUG-B"
        # The signing-pass mutations should sit alongside the debug id —
        # if proc_servicer ever started dropping x-portunus-* it would
        # most likely drop signing-required too, so anchor both.
        assert _decoded_header(raw, "x-portunus-signing-required") == "true"
        assert _decoded_header(raw, "signature").startswith("sig1=")
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_ws_upgrade_request_headers_carry_x_portunus_debug_id():
    """WS upgrade GET: the WS-tagged ext_proc stream still emits a normal.

    request_headers event for the upgrade GET. ``processing_mode`` is
    overridden per-route in proxy/envoy.yaml for the WS route but keeps
    ``request_header_mode: SEND``, so the debug id on the upgrade
    request must land in raw_headers exactly as it does for plain HTTP.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={
                        "x-portunus-debug-id": "DEBUG-C",
                        "upgrade": "websocket",
                        "connection": "upgrade",
                        "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "sec-websocket-version": "13",
                    },
                    is_request=True,
                    websocket_metadata=True,
                    request_id="req-ws",
                )
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        published = publish.of_kind("request_headers")
        assert len(published) == 1
        assert published[0].request_id == "req-ws"
        raw = published[0].payload["headers"]
        assert _decoded_header(raw, "x-portunus-debug-id") == "DEBUG-C"
        assert _decoded_header(raw, "upgrade") == "websocket"
    finally:
        await queue.stop()
