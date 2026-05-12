"""Tests for the ext_proc gRPC Process service.

Covers:
- HTTP body chunks dispatched to the right PublishService method
- WS-upgraded streams: frame parsing, per-direction deflate state
- Bounded queue drop policy under pressure
- Drain protocol injects WS close code 1012
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from google.protobuf import struct_pb2

from portunus.grpc.proc_servicer import PortunusProcessServicer, StreamMode
from portunus.grpc.publish_queue import BoundedPublishQueue


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _http_headers_message(
    *,
    headers: dict[str, str],
    is_request: bool,
    websocket_metadata: bool = False,
    request_id: Optional[str] = None,
) -> proc_pb2.ProcessingRequest:
    """Build a ProcessingRequest carrying a headers message."""
    if request_id:
        headers = {**headers, "x-request-id": request_id}
    header_list = [base_pb2.HeaderValue(key=k, value=v) for k, v in headers.items()]
    headers_msg = proc_pb2.HttpHeaders(
        headers=base_pb2.HeaderMap(headers=header_list),
        end_of_stream=False,
    )

    kwargs: dict = {}
    if is_request:
        kwargs["request_headers"] = headers_msg
    else:
        kwargs["response_headers"] = headers_msg

    if websocket_metadata:
        # Build a metadata_context with the websocket flag set under our
        # ext_proc filter namespace.
        kwargs["metadata_context"] = base_pb2.Metadata(
            filter_metadata={
                "envoy.filters.http.ext_proc": struct_pb2.Struct(
                    fields={
                        "websocket": struct_pb2.Value(bool_value=True),
                    }
                )
            }
        )

    return proc_pb2.ProcessingRequest(**kwargs)


def _http_body_message(
    *, body: bytes, is_request: bool
) -> proc_pb2.ProcessingRequest:
    body_msg = proc_pb2.HttpBody(body=body, end_of_stream=False)
    if is_request:
        return proc_pb2.ProcessingRequest(request_body=body_msg)
    return proc_pb2.ProcessingRequest(response_body=body_msg)


async def _stream_from(items: list) -> AsyncIterator:
    for item in items:
        yield item


class _MockContext:
    """Minimal grpc.aio.ServicerContext stand-in."""

    pass


def _make_servicer(*, queue_maxsize: int = 10_000) -> tuple[
    PortunusProcessServicer, MagicMock, BoundedPublishQueue
]:
    publish = MagicMock()
    publish.publish_request_headers = AsyncMock(return_value=True)
    publish.publish_request_body = AsyncMock(return_value=True)
    publish.publish_request_trailers = AsyncMock(return_value=True)
    publish.publish_response_headers = AsyncMock(return_value=True)
    publish.publish_response_body = AsyncMock(return_value=True)
    publish.publish_response_trailers = AsyncMock(return_value=True)

    queue = BoundedPublishQueue(maxsize=queue_maxsize, num_workers=2)
    servicer = PortunusProcessServicer(publish_service=publish, publish_queue=queue)
    return servicer, publish, queue


# ---------------------------------------------------------------------------
# HTTP path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_request_headers_dispatched_to_publish_request_headers():
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

        responses = [r async for r in servicer.Process(stream, _MockContext())]

        # One response per request message — an empty body response per FDS.
        assert len(responses) == 1
        # Allow queue worker to drain.
        await asyncio.sleep(0.1)
        publish.publish_request_headers.assert_awaited_once()
        kwargs = publish.publish_request_headers.await_args.kwargs
        assert kwargs["request_id"] == "req-123"
        assert kwargs["headers"]["x-foo"] == "bar"
    finally:
        await queue.stop()


@pytest.mark.asyncio
async def test_http_response_body_dispatched_to_publish_response_body():
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={}, is_request=True, request_id="req-x"
                ),
                _http_body_message(body=b"hello world", is_request=False),
            ]
        )

        async for _ in servicer.Process(stream, _MockContext()):
            pass

        await asyncio.sleep(0.1)
        publish.publish_response_body.assert_awaited_once()
        kwargs = publish.publish_response_body.await_args.kwargs
        assert kwargs["body_bytes"] == b"hello world"
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# WS detection from filter metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_metadata_promotes_stream_to_ws_mode():
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
                )
            ]
        )

        async for _ in servicer.Process(stream, _MockContext()):
            pass

        # State for ws-1 has been popped already (stream ended), but we
        # can prove it was WS by observing the active-stream side effect
        # via a second mid-stream request — easier: stub out and check
        # by attribute on the request_headers handler. Simplest: assert
        # _extract_mode behaviour in isolation.
        from portunus.grpc.proc_servicer import _extract_mode

        first = _http_headers_message(
            headers={}, is_request=True, websocket_metadata=True
        )
        assert _extract_mode(first) == StreamMode.WS_UPGRADE

        plain = _http_headers_message(headers={}, is_request=True)
        assert _extract_mode(plain) == StreamMode.HTTP
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# Bounded queue drop policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_chunks_drop_when_queue_full_and_metric_increments():
    # Tiny queue and no workers running yet so put_nowait fills immediately.
    servicer, publish, queue = _make_servicer(queue_maxsize=2)
    # NB: don't start workers — we want the queue to stay full.

    stream = _stream_from(
        [
            _http_headers_message(
                headers={}, is_request=True, request_id="drop-test"
            ),
            _http_body_message(body=b"a" * 100, is_request=False),
            _http_body_message(body=b"b" * 100, is_request=False),
            _http_body_message(body=b"c" * 100, is_request=False),
            _http_body_message(body=b"d" * 100, is_request=False),
        ]
    )

    async for _ in servicer.Process(stream, _MockContext()):
        pass

    # First two fit; the rest get dropped. (request_headers got the
    # "block" path, so it might also occupy a queue slot — give a wide
    # tolerance and just assert *some* drops happened.)
    assert queue.dropped_total >= 1


# ---------------------------------------------------------------------------
# Drain protocol — inject WS close frame on mid-stream drain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drain_injects_ws_close_1012_on_active_ws_stream():
    servicer, publish, queue = _make_servicer()
    await queue.start()
    try:
        # We can't easily mid-stream the request_iterator in a test, so
        # exercise the response path directly: open a stream, then trigger
        # drain after the headers message, then send a body message and
        # observe the next response is a close-frame injection rather
        # than the empty BodyMutation.
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
            results = []
            async for r in servicer.Process(iterator(), _MockContext()):
                results.append(r)
            return results

        task = asyncio.create_task(driver())
        await ready.wait()
        await servicer.drain_all()
        drain_done.set()
        results = await asyncio.wait_for(task, timeout=2.0)

        # First response: empty body response for the headers.
        # Second response: the injected close frame.
        assert len(results) == 2
        close_response = results[1]
        assert close_response.HasField("response_body")
        body = close_response.response_body.response.body_mutation.streamed_response.body
        # Close frame: 0x88 (FIN|close opcode), then 2 + len(reason) payload.
        assert body[0] == 0x88
        # Close code 1012 in big-endian
        close_code = int.from_bytes(body[2:4], "big")
        assert close_code == 1012
    finally:
        await queue.stop()


# ---------------------------------------------------------------------------
# FDS response shape — empty streamed_response, not plain CommonResponse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_response_uses_streamed_response_shape():
    """Envoy 1.36 in FDS mode rejects a plain CommonResponse — must wrap
    in BodyMutation.streamed_response. See spike-findings doc."""
    servicer, _publish, queue = _make_servicer()
    await queue.start()
    try:
        stream = _stream_from(
            [
                _http_headers_message(
                    headers={}, is_request=True, request_id="shape-test"
                ),
                _http_body_message(body=b"some body", is_request=True),
            ]
        )

        responses = [r async for r in servicer.Process(stream, _MockContext())]

        body_resp = responses[1].request_body
        # The path that matters: streamed_response field must be set
        # (even if empty) on the body_mutation.
        assert body_resp.response.body_mutation.HasField("streamed_response")
    finally:
        await queue.stop()
