"""Behaviour tests for the ext_proc gRPC Process servicer.

``PublishService`` is replaced by a ``FakePublishService`` that records
every call's arguments so assertions inspect what was published.
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
from portunus.grpc.proc_servicer import (
    PortunusProcessServicer,
    _header_value,
    _header_value_bytes,
    _headers_to_dict,
)
from portunus.services.publish_queue import BoundedPublishQueue, PublishTask

# ---------------------------------------------------------------------------
# Fake publish service — records what was published.
# ---------------------------------------------------------------------------


@dataclass
class _PublishedItem:
    """One thing the servicer asked Publish to send to Kinesis."""

    kind: str  # "request_headers" | "request_body" | "request_trailers" | ...
    request_id: str
    payload: dict = field(default_factory=dict)


class FakePublishService:
    """Captures every build_* call; ``items`` is the ordered dispatch record.

    build_* records a ``_PublishedItem`` and returns ``(stream_name, bytes)``
    with stream name == kind, so the queue's per-kind stream-grouping is
    exercised. ``put_records`` is a no-op (captured already at build).
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

    async def put_records(self, stream_name: str, records: list[bytes]) -> int:
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
        self.responses: list[proc_pb2.ProcessingResponse] = []
        self.requests = None

    async def read(self):
        try:
            return await self.requests.__anext__()
        except StopAsyncIteration:
            return grpc.aio.EOF

    async def write(self, response):
        self.responses.append(response)

    def invocation_metadata(self) -> list[tuple[str, str]]:
        return self._metadata

    async def abort(self, code, details: str) -> None:
        self.aborted_with = (code, details)


async def _process_responses(servicer, stream, context):
    context.requests = stream.__aiter__()
    await servicer.Process(None, context)
    for response in context.responses:
        yield response


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
        batch_sender=publish.put_records,
    )
    servicer = PortunusProcessServicer(
        publish_service=publish,  # type: ignore[arg-type]
        publish_queue=queue,
    )
    return servicer, publish, queue


async def _drain_queue(queue: BoundedPublishQueue, *, timeout: float = 1.0) -> None:
    """Wait for the queue to fully drain so publish-side assertions see every.

    dispatched item (avoids a wall-clock-dependent fixed sleep).
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        request_headers = publish.of_kind("request_headers")
        assert len(request_headers) == 1
        assert request_headers[0].request_id == "req-123"
        # Wire format is base64-encoded for the downstream analytics
        # pipeline's compatibility — see _headers_to_dict in proc_servicer.
        encoded = request_headers[0].payload["headers"]["user-agent"]
        assert base64.b64decode(encoded).decode() == "curl/8.5"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_headers_are_read_from_raw_value_field_when_value_is_empty():
    """Envoy 1.20+ populates raw_value (bytes) and leaves deprecated ``value`` empty.

    The servicer must read raw_value (else an empty x-request-id loses join-key
    correlation across audit records).
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
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
    """Strip the credential-carrying headers before publishing audit records.

    ext_proc observes headers AFTER ext_authz rewrites ``Authorization`` to
    the real upstream provider API key, so publishing verbatim would archive
    secrets. ``KNOWN_AUTH_HEADERS`` (default: authorization, x-api-key,
    x-goog-api-key, api-key) and the configured ``api_key_header`` are
    dropped; every other header, custom ones included, is captured.
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
                        "user-agent": "curl/8.5",
                        "x-aisi-team": "red",
                        "x-test-marker": "marker-1",
                    },
                    is_request=True,
                    request_id="req-redact",
                )
            ]
        )

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        request_headers = publish.of_kind("request_headers")
        assert len(request_headers) == 1
        published = request_headers[0].payload["headers"]
        for name in ("authorization", "x-api-key", "api-key", "x-goog-api-key"):
            assert name not in published
        assert base64.b64decode(published["user-agent"]).decode() == "curl/8.5"
        assert base64.b64decode(published["x-aisi-team"]).decode() == "red"
        assert base64.b64decode(published["x-test-marker"]).decode() == "marker-1"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_credential_headers_are_redacted_from_published_response_headers():
    """Redaction also applies to the response side.

    An upstream can echo request-side credential headers, which must not be
    archived; other response headers are.
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
                        "authorization": "Bearer leftover",
                        "x-api-key": "sk-leak",
                        "api-key": "azure-echo",
                        "x-goog-api-key": "google-echo",
                        "server": "istio-envoy",
                        "x-aisi-upstream": "echoed",
                    },
                    is_request=False,
                ),
            ]
        )

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        response_headers = publish.of_kind("response_headers")
        assert len(response_headers) == 1
        published = response_headers[0].payload["headers"]
        for name in ("authorization", "x-api-key", "api-key", "x-goog-api-key"):
            assert name not in published
        assert base64.b64decode(published["server"]).decode() == "istio-envoy"
        assert base64.b64decode(published["x-aisi-upstream"]).decode() == "echoed"
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        response_bodies = publish.of_kind("response_body")
        assert len(response_bodies) == 1
        assert response_bodies[0].payload["body_bytes"] == b"hello world"
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Bounded queue drop policy — under back-pressure, drop body chunks rather
# than blocking the customer's request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_chunks_are_dropped_when_publish_queue_is_full(monkeypatch):
    """Body submits drop when queue capacity is exceeded so a slow Kinesis stream.

    can't backpressure customer traffic. Observation messages produce no replies;
    drops still register on the queue.
    Setup: tiny queue + no workers so it stays full.
    """
    servicer, _publish, queue = _make_servicer(queue_maxsize=2)
    # Workers deliberately not started so the queue stays full.

    messages = [
        _http_headers_message(headers={}, is_request=True, request_id="drop-test"),
        _http_body_message(body=b"a" * 100, is_request=False),
        _http_body_message(body=b"b" * 100, is_request=False),
        _http_body_message(body=b"c" * 100, is_request=False),
        _http_body_message(body=b"d" * 100, is_request=False, end_of_stream=True),
    ]
    for message in messages:
        message.observability_mode = True
    stream = _stream_from(messages)

    responses = [r async for r in _process_responses(servicer, stream, _ctx_with_key())]

    assert responses == []
    assert queue.dropped_total >= 1


@pytest.mark.asyncio
async def test_body_drop_leaves_a_chunk_id_gap_and_counts_the_drop():
    """A dropped chunk is counted and leaves a gap; no marker record is sent.

    Consumers detect it from the chunk_ids: a body is complete iff they are
    contiguous from 0 through the record with ``final_chunk=True``.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        original_submit = queue.submit_droppable
        calls = 0

        def _fake_submit(task):
            # Drop the second body chunk only.
            nonlocal calls
            calls += 1
            if calls == 2:
                queue._dropped_total += 1
                return False
            return original_submit(task)

        queue.submit_droppable = _fake_submit  # type: ignore[assignment]

        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="gap"),
                _http_body_message(body=b"first", is_request=False),
                _http_body_message(body=b"second", is_request=False),
                _http_body_message(body=b"third", is_request=False, end_of_stream=True),
            ]
        )
        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("response_body")
        assert [b.payload["chunk_id"] for b in bodies] == [0, 2]
        assert [b.payload["body_bytes"] for b in bodies] == [b"first", b"third"]
        assert queue.dropped_total == 1
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

        responses = [r async for r in _process_responses(servicer, stream, ctx)]

        assert responses == []
        assert ctx.aborted_with is not None
        code, detail = ctx.aborted_with
        assert code == grpc.StatusCode.PERMISSION_DENIED
        assert "proxy identity" in detail.lower()
        # Nothing published for a stream that never proved its identity.
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

        responses = [r async for r in _process_responses(servicer, stream, ctx)]

        assert responses == []
        assert ctx.aborted_with[0] == grpc.StatusCode.PERMISSION_DENIED
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# ProcessingResponse shape follows the incoming protocol mode.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_events_yield_no_processing_response_under_observability_mode():
    """Observation mode captures headers and body chunks without replying."""
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        messages = [
            _http_headers_message(headers={}, is_request=True, request_id="shape"),
            _http_body_message(body=b"first", is_request=True),
            _http_body_message(body=b"last", is_request=True, end_of_stream=True),
        ]
        for message in messages:
            message.observability_mode = True
        stream = _stream_from(messages)

        responses = [
            r async for r in _process_responses(servicer, stream, _ctx_with_key())
        ]

        assert responses == []
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_headers_response_uses_headers_field_not_body_field():
    """A headers message needs a HeadersResponse on the matching oneof field.

    The field must be request_headers/response_headers; a BodyResponse triggers
    Envoy "Spurious response message 3" and fails the filter with 500.
    """
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(headers={}, is_request=True, request_id="shape"),
            ]
        )

        responses = [
            r async for r in _process_responses(servicer, stream, _ctx_with_key())
        ]

        assert len(responses) == 1
        assert responses[0].HasField("request_headers")
        assert not responses[0].HasField("request_body")
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Body chunking — each ext_proc body message lands as one audit record
# with a monotonic chunk_id and ``num_chunks=0`` (sentinel); the Glue ETL
# reassembles them per request_id.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_streamed_body_chunks_have_monotonic_ids_and_sentinel_num_chunks():
    """Each response_body message becomes its own audit record.

    Records have a sequential per-direction ``chunk_id`` and ``num_chunks=0``,
    so portunus holds no body state and SSE responses reach Kinesis as they arrive.
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
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
        # Only the end_of_stream chunk is marked final — the end-of-body signal
        # the num_chunks=0 sentinel lacks, letting ETL detect a missing tail.
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("request_body")
        assert len(bodies) > 1
        assert [b.payload["chunk_id"] for b in bodies] == list(range(len(bodies)))
        assert [b.payload["num_chunks"] for b in bodies] == [0] * len(bodies)
        assert b"".join(b.payload["body_bytes"] for b in bodies) == body
        # One end_of_stream HttpBody split across records marks final_chunk on
        # exactly the last record, so ETL's max-chunk_id completeness check holds.
        finals = [b.payload["final_chunk"] for b in bodies]
        assert finals == [False] * (len(bodies) - 1) + [True]
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_request_and_response_chunk_ids_are_independent_per_direction():
    """Request- and response-side ``chunk_id`` counters are separate, so both.

    directions can legitimately start at ``chunk_id=0``, disambiguated by the
    stream (direction) each record is published to.
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
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
    """If the stream ends without an ``end_of_stream`` chunk (client.

    disconnect, upstream reset), every chunk that arrived is already published
    (no portunus-side buffer to lose); ETL yields a partial-body record.
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        bodies = publish.of_kind("response_body")
        assert [b.payload["body_bytes"] for b in bodies] == [b"partial-", b"body"]
        assert [b.payload["chunk_id"] for b in bodies] == [0, 1]
        # No chunk carried end_of_stream, so none is final and ETL treats the
        # body as truncated.
        assert [b.payload["final_chunk"] for b in bodies] == [False, False]
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_final_chunk_marks_terminal_chunk_per_direction():
    """Each direction's end_of_stream chunk is marked ``final_chunk=True``.

    independently, since request and response bodies stream on separate
    chunk_id counters and ETL reassembles them separately.
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

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
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
    """Two concurrent streams sharing an x-request-id must register.

    independently. Envoy can preserve a client-supplied x-request-id, so
    keying the registry by request_id would let one overwrite the other
    (losing a summary on close); keying by internal stream_id fixes it.
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
            return [r async for r in _process_responses(servicer, it, _ctx_with_key())]

        task_a = asyncio.create_task(driver(iterator(ready_a, hold_a)))
        task_b = asyncio.create_task(driver(iterator(ready_b, hold_b)))
        await ready_a.wait()
        await ready_b.wait()

        # Both in the registry under distinct stream_ids despite the shared id.
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
    """Binary header values (e.g. Sec-WebSocket-Key) pass through to base64.

    without UTF-8 decoding, so consumers recover the exact original bytes.
    """
    raw = bytes(range(256))  # every byte 0x00..0xff
    # A non-credential header name, so it survives _headers_to_dict.
    h = base_pb2.HeaderValue(key="sec-websocket-key", raw_value=raw)
    assert _header_value_bytes(h) == raw

    header_map = base_pb2.HeaderMap(headers=[h])
    encoded = _headers_to_dict(header_map)["sec-websocket-key"]
    assert base64.b64decode(encoded) == raw


def test_header_value_bytes_warns_when_raw_and_legacy_diverge(caplog):
    """When raw_value and value differ, raw_value wins and a warning is logged.

    An operator can spot the non-conforming Envoy's divergence rather than
    losing it silently.
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
    """``_header_value`` is the lossy str view for string-identifier callers.

    Non-UTF-8 becomes U+FFFD; the lossless path is ``_header_value_bytes``.
    """
    h = base_pb2.HeaderValue(key="x-bin", raw_value=b"\xff\xfe\xfd")
    decoded = _header_value(h)
    assert "�" in decoded


# ---------------------------------------------------------------------------
# x-portunus-debug-id propagation — the servicer must surface the header
# verbatim (base64) for every ext_proc stream shape (HTTP,
# WS upgrade GET) so the integrity checker can correlate it with request_id.
# Envoy strips it in the router (terminal) filter, after ext_proc runs, so
# ext_proc is the audit trail's only chance to capture it.
# ---------------------------------------------------------------------------


def _decoded_header(headers_dict: dict[str, str], key: str) -> str:
    return base64.b64decode(headers_dict[key]).decode()


@pytest.mark.asyncio
async def test_http_request_headers_carry_x_portunus_debug_id():
    """Baseline: plain HTTP request carries the debug id into raw_headers."""
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={"x-portunus-debug-id": "DEBUG-A"},
                    is_request=True,
                    request_id="req-http",
                )
            ]
        )

        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
        await _drain_queue(queue)

        published = publish.of_kind("request_headers")
        assert len(published) == 1
        assert published[0].request_id == "req-http"
        assert (
            _decoded_header(published[0].payload["headers"], "x-portunus-debug-id")
            == "DEBUG-A"
        )
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_header_carrying_the_upstream_credential_is_never_captured():
    """A secret's ``output_header`` may name a header that is otherwise captured.

    ext_authz reports which header it wrote the credential to; ext_proc must
    drop that header from the captured request headers whatever its name.
    """
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        message = _http_headers_message(
            headers={
                "x-request-id": "sk-minted-credential",
                "content-type": "application/json",
            },
            is_request=True,
        )
        message.metadata_context.filter_metadata[
            "envoy.filters.http.ext_authz"
        ].CopyFrom(
            struct_pb2.Struct(
                fields={
                    "upstream_auth_header": struct_pb2.Value(
                        string_value="X-Request-Id"
                    )
                }
            )
        )

        async for _ in _process_responses(
            servicer, _stream_from([message]), _ctx_with_key()
        ):
            pass
        await _drain_queue(queue)

        raw = publish.of_kind("request_headers")[0].payload["headers"]
        assert "x-request-id" not in raw
        assert _decoded_header(raw, "content-type") == "application/json"
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Header capture: a denylist of credential headers, everything else recorded
# ---------------------------------------------------------------------------

_DEFAULT_KNOWN_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
}


def _header_map(headers: dict[str, str]) -> base_pb2.HeaderMap:
    return base_pb2.HeaderMap(
        headers=[base_pb2.HeaderValue(key=k, value=v) for k, v in headers.items()]
    )


def test_default_known_auth_headers_match_the_proxys_old_default():
    """The backend's default is the list the proxy entrypoint used to carry."""
    assert portunus_config.known_auth_headers == frozenset(_DEFAULT_KNOWN_AUTH_HEADERS)


@pytest.mark.parametrize("credential_header", sorted(_DEFAULT_KNOWN_AUTH_HEADERS))
def test_known_auth_headers_are_never_captured(credential_header):
    assert _headers_to_dict(_header_map({credential_header: "secret"})) == {}


@pytest.mark.parametrize("api_key_header", ["authorization", "x-custom-tenant-key"])
def test_the_configured_api_key_header_is_never_captured(monkeypatch, api_key_header):
    """The header the payload arrives in is dropped whatever it is set to."""
    monkeypatch.setattr(portunus_config, "api_key_header", api_key_header)

    captured = _headers_to_dict(
        _header_map({api_key_header: "the-configured-key-location", "x-foo": "bar"})
    )

    assert api_key_header not in captured
    assert captured.keys() == {"x-foo"}


def test_the_upstream_credential_header_is_dropped_only_when_named():
    """A per-secret ``output_header`` such as ElevenLabs' is redacted by name."""
    headers = _header_map({"xi-api-key": "eleven-sk", "content-type": "text/plain"})

    assert "xi-api-key" in _headers_to_dict(headers)
    assert _headers_to_dict(headers, also_redact="XI-API-Key").keys() == {
        "content-type"
    }


def test_known_auth_headers_can_be_extended_or_replaced(monkeypatch):
    """``KNOWN_AUTH_HEADERS`` is operator configuration, not a fixed list."""
    monkeypatch.setattr(
        portunus_config, "known_auth_headers", frozenset({"cookie", "x-custom-key"})
    )

    captured = _headers_to_dict(
        _header_map(
            {
                "cookie": "session=s",
                "x-custom-key": "k",
                # Not in the configured list any more, so it is captured; the
                # payload header (api_key_header) is still dropped.
                "x-api-key": "sk-anthropic",
                "authorization": "Bearer payload",
            }
        )
    )

    assert captured.keys() == {"x-api-key"}


def test_header_matching_is_case_insensitive():
    captured = _headers_to_dict(
        _header_map(
            {
                "Authorization": "Bearer sk",
                "X-API-Key": "sk",
                "X-Test-Marker": "m",
                "X-AISI-Team": "red",
            }
        )
    )

    assert captured.keys() == {"x-test-marker", "x-aisi-team"}


def test_custom_headers_are_captured():
    """Capture is a denylist: anything not named as a credential is recorded."""
    headers = {
        "x-aisi-team": "red",
        "x-test-marker": "marker",
        "x-newprovider-key": "not-a-known-credential-header",
        "openai-organization": "org-123",
        "content-type": "application/json",
        ":method": "POST",
        "x-portunus-debug-id": "DEBUG-1",
        "anthropic-ratelimit-tokens-remaining": "1000",
    }

    captured = _headers_to_dict(_header_map(headers))

    assert captured.keys() == headers.keys()
    assert base64.b64decode(captured["x-aisi-team"]).decode() == "red"


def test_known_auth_headers_env_is_parsed_case_insensitively(monkeypatch):
    from portunus.config import get_config

    monkeypatch.setenv("KNOWN_AUTH_HEADERS", " Cookie , X-Custom-Key,, ")
    get_config.cache_clear()
    try:
        assert get_config().known_auth_headers == frozenset({"cookie", "x-custom-key"})
    finally:
        get_config.cache_clear()


# ---------------------------------------------------------------------------
# Body saturation: a lost chunk counts exactly once on dropped_total, and
# header/metadata records still land in the reserved headroom
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_saturation_counts_one_drop_and_headers_use_the_headroom():
    servicer, _publish, queue = _make_servicer(queue_maxsize=12)
    # Default body_capacity is 90% of maxsize = 10. Saturate the body tier,
    # leaving the blocking headroom (2 slots) free.
    for _ in range(10):
        assert queue.submit_droppable(
            PublishTask(build=lambda: ("body", b"{}\n"), label="filler")
        )

    stream = _stream_from(
        [
            _http_headers_message(headers={}, is_request=True, request_id="sat"),
            _http_body_message(body=b"lost-chunk", is_request=False),
        ]
    )
    dropped_before = queue.dropped_total
    async for _ in _process_responses(servicer, stream, _ctx_with_key()):
        pass

    assert queue.dropped_total == dropped_before + 1
    assert queue.qsize() == 11  # 10 fillers + the headers record in the headroom


@pytest.mark.asyncio
async def test_blocking_submits_time_out_instead_of_stalling_process(monkeypatch):
    """A blocked header publish times out and counts the dropped record."""
    monkeypatch.setattr(portunus_config.grpc, "publish_blocking_timeout_seconds", 0.05)
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
    # Two blocked header submits must complete in ~2 timeouts, not hang.
    async with asyncio.timeout(2.0):
        async for _ in _process_responses(servicer, stream, _ctx_with_key()):
            pass
    elapsed = loop.time() - t0

    assert elapsed < 1.0
    # Both header records were dropped-with-timeout and counted.
    assert queue.dropped_total == 2
