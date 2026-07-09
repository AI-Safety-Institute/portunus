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
from portunus.services.publish_queue import BoundedPublishQueue, PublishTask

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
    """Captures every build_* call. ``items`` is the ordered record of.

    everything the servicer dispatched.

    The real PublishService.build_* methods synchronously return
    ``(stream_name, data_bytes)`` and the queue worker ships them via
    ``put_record_batch``. Here build_* records a ``_PublishedItem`` (so the
    existing ``of_kind`` assertions keep working) and returns a tuple whose
    stream name *is* the kind — so the queue's stream-grouping is exercised
    too. ``put_record_batch`` is a no-op (items already captured at build).
    """

    def __init__(self) -> None:
        self.items: list[_PublishedItem] = []
        self.batches: list[tuple[str, int]] = []  # (stream, record_count)

    def _builder(self, kind: str):
        def _impl(**kwargs):
            self.items.append(
                _PublishedItem(
                    kind=kind,
                    request_id=kwargs.get("request_id", ""),
                    payload={k: v for k, v in kwargs.items() if k != "request_id"},
                )
            )
            # Stream name == kind so the worker groups per kind; the bytes
            # are opaque to these tests (they assert on captured payloads).
            return kind, b"{}\n"

        return _impl

    async def put_record_batch(self, stream_name: str, records: list[bytes]) -> int:
        self.batches.append((stream_name, len(records)))
        return 0  # nothing failed

    def __getattr__(self, name: str):
        if name.startswith("build_"):
            return self._builder(name[len("build_") :])
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
    queue = BoundedPublishQueue(
        maxsize=queue_maxsize,
        num_workers=2,
        batch_sender=publish.put_record_batch,
    )
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
                    headers={"user-agent": "curl/8.5"},
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
        encoded = request_headers[0].payload["headers"]["user-agent"]
        assert base64.b64decode(encoded).decode() == "curl/8.5"
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
            base_pb2.HeaderValue(key="user-agent", raw_value=b"curl/8.5"),
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
        encoded = published[0].payload["headers"]["user-agent"]
        assert base64.b64decode(encoded).decode() == "curl/8.5"
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
                        "api-key": "azure-sk",
                        "x-goog-api-key": "google-sk",
                        "xi-api-key": "eleven-sk",
                        "x-hume-api-key": "hume-sk",
                        "cookie": "session=secret-session",
                        "proxy-authorization": "Basic dXNlcjpwYXNz",
                        "x-amz-security-token": "FQoGZX...EXAMPLE",
                        "user-agent": "curl/8.5",
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
        assert "api-key" not in published
        assert "x-goog-api-key" not in published
        assert "xi-api-key" not in published
        assert "x-hume-api-key" not in published
        assert "cookie" not in published
        assert "proxy-authorization" not in published
        assert "x-amz-security-token" not in published
        # Non-sensitive, allowlisted headers are preserved.
        encoded = published["user-agent"]
        assert base64.b64decode(encoded).decode() == "curl/8.5"
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
                        "api-key": "azure-echo",
                        "x-goog-api-key": "google-echo",
                        "cookie": "tracker=xyz",
                        "proxy-authorization": "Basic dXNlcjpwYXNz",
                        "x-amz-security-token": "FQoGZX...EXAMPLE",
                        "server": "istio-envoy",
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
        assert "api-key" not in published
        assert "x-goog-api-key" not in published
        assert "cookie" not in published
        assert "proxy-authorization" not in published
        assert "x-amz-security-token" not in published
        encoded = published["server"]
        assert base64.b64decode(encoded).decode() == "istio-envoy"
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


@pytest.mark.asyncio
async def test_pre_101_poisoned_stream_skips_replay_and_observation():
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
    await servicer._replay_pre_101(state, "2026-01-01T00:00:00Z")
    # A subsequent under-cap chunk must still be ignored (no re-buffering).
    servicer._buffer_pre_101(state, Direction.REQUEST, b"small")
    assert state.pre_101_buffer == []


# ---------------------------------------------------------------------------
# Bounded queue drop policy — under back-pressure, drop body chunks rather
# than blocking the customer's request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_chunks_are_dropped_when_publish_queue_is_full(monkeypatch):
    """With per-chunk publishing, body submits use ``put_nowait`` and.

    drop when capacity is exceeded — exactly so a slow Firehose can't
    backpressure customer traffic. Tiny queue + no workers + a few
    body chunks → drop_total increments.

    Under ``observability_mode: true`` body events do not yield a
    ProcessingResponse (Envoy ignores them); only the request_headers
    event does. Drops continue to happen on the publish queue.
    """
    # Keep the drop-sentinel blocking submits from stalling the test on the
    # deliberately saturated queue.
    monkeypatch.setattr(
        portunus_config.grpc, "drop_sentinel_timeout_seconds", 0.02
    )
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
        finals = [b.payload["final_chunk"] for b in bodies]
        assert ids == [0, 1, 2]
        assert nums == [0, 0, 0]
        assert body_bytes == [b"chunk-a", b"chunk-b", b"chunk-c"]
        # Only the terminal chunk (the one carrying end_of_stream) is marked —
        # this is the end-of-body signal the num_chunks=0 sentinel format lacks,
        # so the Glue ETL can tell a complete body from one missing its tail.
        assert finals == [False, False, True]
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
        # A single end_of_stream HttpBody split across many Firehose records
        # marks final_chunk on exactly the last record — not every sub-chunk —
        # so the ETL's "marker on the max chunk_id" completeness check holds.
        finals = [b.payload["final_chunk"] for b in bodies]
        assert finals == [False] * (len(bodies) - 1) + [True]
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
        # No chunk carried end_of_stream, so none is marked final — the ETL
        # sees no terminal marker and (correctly) treats the body as truncated.
        assert [b.payload["final_chunk"] for b in bodies] == [False, False]
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_final_chunk_marks_terminal_chunk_per_direction():
    """The end_of_stream chunk of each direction is marked final independently.

    Request and response bodies stream on separate chunk_id counters, so each
    direction's terminal chunk carries its own ``final_chunk=True`` — the ETL
    reassembles the two bodies separately and needs an end-of-body marker for
    each.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="eos-1"),
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

        req_finals = [b.payload["final_chunk"] for b in publish.of_kind("request_body")]
        resp_finals = [
            b.payload["final_chunk"] for b in publish.of_kind("response_body")
        ]
        assert req_finals == [False, True]
        assert resp_finals == [False, True]
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
    # Use an allowlisted header name so it survives _headers_to_dict.
    h = base_pb2.HeaderValue(key="sec-websocket-key", raw_value=raw)
    assert _header_value_bytes(h) == raw

    header_map = base_pb2.HeaderMap(headers=[h])
    encoded = _headers_to_dict(header_map)["sec-websocket-key"]
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
async def test_ws_frames_carry_monotonic_per_direction_frame_index():
    """Each WS frame gets a distinct per-direction frame_index.

    Downstream Glue keys WS frames by (request_id, frame_index); without a
    distinct index, identical same-timestamp frames collide on the body-hash
    row key and get dropped by dedup (the H1 undercount). Assert successive
    frames in one direction get 0, 1, ... and HTTP bodies leave it None.
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
                    request_id="ws-fi-1",
                ),
                _http_headers_message(headers={}, is_request=False),
                # Two server frames with IDENTICAL payloads — the exact case
                # that would collide without frame_index.
                _http_body_message(body=_ws_frame(b"dup"), is_request=False),
                _http_body_message(body=_ws_frame(b"dup"), is_request=False),
            ]
        )
        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        resp = publish.of_kind("response_body")
        frame_indices = [item.payload.get("frame_index") for item in resp]
        # Two identical-payload frames must still get distinct, monotonic
        # per-direction frame_index values (0, 1).
        assert frame_indices == [0, 1], frame_indices
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_http_body_records_have_no_frame_index():
    """HTTP (non-WS) body records leave frame_index None."""
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={}, is_request=False, request_id="http-1"
                ),
                _http_body_message(body=b"plain-http-body", is_request=False),
            ]
        )
        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        resp = publish.of_kind("response_body")
        assert resp, "expected a response_body record"
        assert all(item.payload.get("frame_index") is None for item in resp), resp
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

    async def _capture_blocking(task, **kwargs):
        blocking_labels.append(task.label)
        await original_blocking(task, **kwargs)

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


# ---------------------------------------------------------------------------
# Redaction regression (PR #32 reviewed set) + capture allowlist
# ---------------------------------------------------------------------------

_PR32_DENYLIST = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "xi-api-key",
    "x-hume-api-key",
    "x-amz-security-token",
}


def _header_map(headers: dict[str, str]) -> base_pb2.HeaderMap:
    return base_pb2.HeaderMap(
        headers=[base_pb2.HeaderValue(key=k, value=v) for k, v in headers.items()]
    )


@pytest.mark.parametrize(
    "api_key_header",
    ["authorization", "x-api-key", "x-custom-tenant-key", "API-KEY"],
)
def test_pr32_denylist_headers_never_captured_under_any_api_key_header(
    monkeypatch, api_key_header
):
    """Regression for the #19 redaction narrowing (security HIGH / C4).

    PR #32's security-reviewed denylist redacted ``api-key`` (Azure),
    ``x-goog-api-key`` (Google), ``xi-api-key`` (ElevenLabs),
    ``x-hume-api-key`` (Hume) and a *hardcoded* ``authorization`` literal.
    The #19 rewrite dropped the four provider headers entirely and made
    ``authorization`` redacted only when it happened to equal the configured
    ``API_KEY_HEADER``. Pin: the full #32 set is redacted under ANY
    ``API_KEY_HEADER`` value, and the configured header itself is redacted
    whatever it is set to.
    """
    monkeypatch.setattr(portunus_config, "api_key_header", api_key_header)

    captured = _headers_to_dict(
        _header_map(
            {
                "authorization": "Bearer sk-REALSECRET",
                "proxy-authorization": "Basic dXNlcjpwYXNz",
                "cookie": "session=s",
                "set-cookie": "session=s; HttpOnly",
                "x-api-key": "sk-anthropic",
                "api-key": "azure-sk",
                "x-goog-api-key": "google-sk",
                "xi-api-key": "eleven-sk",
                "x-hume-api-key": "hume-sk",
                "x-amz-security-token": "FQoGZX...EXAMPLE",
                api_key_header.lower(): "the-configured-key-location",
                "user-agent": "curl/8.5",
            }
        )
    )

    leaked = _PR32_DENYLIST & set(captured)
    assert not leaked, f"credential headers leaked to capture: {leaked}"
    assert api_key_header.lower() not in captured
    # The capture still works for safe headers.
    assert "user-agent" in captured


def test_unknown_headers_are_dropped_by_the_capture_allowlist():
    """Capture is allowlist-based: a header we haven't classified is NOT.

    archived. This is the structural fix for the denylist-by-omission leak —
    a newly onboarded provider's bespoke credential header (e.g.

    ``x-newprovider-key``) can never leak just because nobody added it to a
    blocklist.
    """
    captured = _headers_to_dict(
        _header_map(
            {
                "x-newprovider-key": "sk-brand-new-provider",
                "x-foo": "bar",
                "openai-organization": "org-123",
                "content-type": "application/json",
                ":method": "POST",
                "x-portunus-debug-id": "DEBUG-1",
                "x-portunus-signing-required": "true",
                # A client-forged x-portunus-* header must NOT ride an
                # x-portunus- prefix rule into the audit lake — only the
                # two enumerated Portunus control-plane headers above are
                # captured.
                "x-portunus-forged-role": "admin",
                "x-portunus-api-key": "sk-smuggled",
                "anthropic-ratelimit-tokens-remaining": "1000",
            }
        )
    )

    assert "x-newprovider-key" not in captured
    assert "x-foo" not in captured
    assert "openai-organization" not in captured
    assert "x-portunus-forged-role" not in captured
    assert "x-portunus-api-key" not in captured
    # Allowlisted analytics headers survive (exact names and prefixes —
    # the x-portunus entries are ENUMERATED, not a prefix rule).
    assert set(captured) == {
        "content-type",
        ":method",
        "x-portunus-debug-id",
        "x-portunus-signing-required",
        "anthropic-ratelimit-tokens-remaining",
    }


# ---------------------------------------------------------------------------
# Drop sentinel: survives body saturation via the blocking headroom, and
# one logical lost chunk counts exactly once on dropped_total
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drop_sentinel_survives_body_saturation_and_lands_in_publish():
    """Under body saturation the ``dropped=True`` marker must still enqueue.

    Pre-fix the sentinel was submitted on the same ``submit_droppable`` path
    at the very instant ``qsize >= body_capacity`` — so under the exact
    condition it exists to signal, it was dropped too (99 drop warnings, 0
    markers in S3 in the load test). Now it rides ``submit_blocking`` into
    the reserved headroom.
    """
    servicer, publish, queue = _make_servicer(queue_maxsize=12)
    # Default body_capacity is 90% of maxsize = 10. Saturate the body tier,
    # leaving the blocking headroom (2 slots) free.
    for _ in range(10):
        assert queue.submit_droppable(
            PublishTask(build=lambda: ("body", b"{}\n"), label="filler")
        )
    assert queue.qsize() == 10

    stream = _stream_from(
        [
            _http_headers_message(
                headers={}, is_request=True, request_id="sat-sentinel"
            ),
            _http_body_message(body=b"lost-chunk", is_request=False),
        ]
    )
    dropped_before = queue.dropped_total
    async for _ in servicer.Process(stream, _ctx_with_key()):
        pass

    # The real chunk was dropped (queue at body capacity)...
    assert queue.dropped_total == dropped_before + 1
    # ...but exactly once for the logical chunk: the sentinel is accounted
    # separately and must NOT double-count.
    assert queue.sentinel_dropped_total == 0
    # The sentinel landed in the blocking headroom above body_capacity.
    assert queue.qsize() == 12  # 10 fillers + headers record + sentinel

    # Drain and confirm the marker reaches the publish layer.
    await queue.start()
    await _drain_queue(queue, timeout=2.0)
    await queue.stop()
    sentinels = [
        b for b in publish.of_kind("response_body") if b.payload.get("dropped")
    ]
    assert len(sentinels) == 1
    assert sentinels[0].payload["body_bytes"] == b""


@pytest.mark.asyncio
async def test_sentinel_timeout_under_true_saturation_counts_sentinel_dropped(
    monkeypatch,
):
    """If even the blocking sentinel can't land (queue completely full), the.

    loss is counted on ``sentinel_dropped_total`` — never a second increment
    of ``dropped_total`` for the same logical chunk.
    """
    monkeypatch.setattr(portunus_config.grpc, "drop_sentinel_timeout_seconds", 0.05)
    servicer, _publish, queue = _make_servicer(queue_maxsize=2)
    # Fill the queue completely (headers record takes one slot; fill the rest).
    stream = _stream_from(
        [
            _http_headers_message(headers={}, is_request=True, request_id="full"),
            _http_body_message(body=b"chunk-a", is_request=False),
            _http_body_message(body=b"chunk-b", is_request=False),
        ]
    )
    async for _ in servicer.Process(stream, _ctx_with_key()):
        pass

    # headers → slot 1 (blocking). chunk-a: body_capacity=1, qsize already 1
    # → dropped; its sentinel lands in slot 2 (blocking headroom). chunk-b:
    # dropped; its sentinel finds the queue full and times out.
    assert queue.dropped_total == 2  # exactly one per logical lost chunk
    assert queue.sentinel_dropped_total == 1


# ---------------------------------------------------------------------------
# WS parse-error / deflate-cap: desync is accounted, not silent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_parse_error_bumps_truncated_counter_and_summary_reflects_it():
    """A malformed WS frame desyncs the parser for that direction. Pre-fix the.

    observer logged and went silent — the WSSummaryRecord then reported clean
    counts while the rest of the session went unobserved (audit MEDIUM). Now
    the transition bumps the per-direction truncated counter once, so the
    summary reflects the observation gap.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        # 0x8F = FIN + unknown opcode 0xF → wsproto ParseFailed.
        malformed = bytes([0x8F, 0x02]) + b"xx"
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={},
                    is_request=True,
                    websocket_metadata=True,
                    request_id="ws-desync",
                ),
                _http_headers_message(headers={}, is_request=False),
                _http_body_message(body=_ws_frame(b"before"), is_request=False),
                _http_body_message(body=malformed, is_request=False),
                # After desync nothing in this direction is observable; this
                # frame must neither crash nor emit records.
                _http_body_message(body=_ws_frame(b"after"), is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        # The frame before the poison was observed; the one after was not.
        payloads = [
            b.payload.get("body_bytes") for b in publish.of_kind("response_body")
        ]
        assert b"before" in payloads
        assert b"after" not in payloads

        summaries = publish.of_kind("ws_summary")
        assert len(summaries) == 1
        record = summaries[0].payload["record"]
        # The desync is visible downstream: exactly one truncation marker for
        # the blinded direction (not one per subsequent frame).
        assert record.truncated_server_frames == 1
        assert record.truncated_client_frames == 0
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_blocking_submits_time_out_instead_of_stalling_process(monkeypatch):
    """A wedged sink must not pin the Process coroutine on a header submit.

    With the queue completely full and no workers draining, the
    header/metadata/trailer/summary submits are bounded by
    ``publish_blocking_timeout_seconds`` — the stream completes promptly
    and the timed-out records are counted as dropped (observable loss)
    rather than wedging the stream (and, at stream end, the drain).
    """
    monkeypatch.setattr(
        portunus_config.grpc, "publish_blocking_timeout_seconds", 0.05
    )
    monkeypatch.setattr(portunus_config.grpc, "drop_sentinel_timeout_seconds", 0.02)
    servicer, _publish, queue = _make_servicer(queue_maxsize=1)
    # Fill the queue completely; workers deliberately not started.
    assert (
        await queue.submit_blocking(
            PublishTask(build=lambda: ("body", b"{}\n"), label="filler")
        )
        is True
    )
    assert queue.qsize() == 1

    stream = _stream_from(
        [
            _http_headers_message(headers={}, is_request=True, request_id="wedged"),
            _http_headers_message(headers={}, is_request=False),
        ]
    )

    loop = asyncio.get_event_loop()
    t0 = loop.time()
    # The whole stream (2 blocked header submits) must complete in ~2
    # timeouts, not hang forever awaiting queue space.
    async with asyncio.timeout(2.0):
        async for _ in servicer.Process(stream, _ctx_with_key()):
            pass
    elapsed = loop.time() - t0

    assert elapsed < 1.0
    # Both header records were dropped-with-timeout and counted.
    assert queue.dropped_total == 2


@pytest.mark.asyncio
async def test_ws_summary_submit_times_out_on_wedged_queue(monkeypatch):
    """The WS-summary submit in Process's ``finally`` is bounded too.

    That submit runs at stream end — including during drain — so an
    unbounded put on a wedged sink would pin the drain forever.
    """
    monkeypatch.setattr(
        portunus_config.grpc, "publish_blocking_timeout_seconds", 0.05
    )
    servicer, _publish, queue = _make_servicer(queue_maxsize=1)
    state = _StreamState(
        stream_id="ws-wedged",
        request_id="ws-wedged",
        mode=StreamMode.WS_UPGRADE,
    )
    assert (
        await queue.submit_blocking(
            PublishTask(build=lambda: ("body", b"{}\n"), label="filler")
        )
        is True
    )

    async with asyncio.timeout(1.0):
        await servicer._emit_ws_summary(state, droppable=False)

    assert state.summary_emitted is True
    assert queue.dropped_total == 1  # the summary was shed, counted, logged
