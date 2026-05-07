"""Behavior tests for the ext_proc WebSocket relay handler.

The contract under test is the ExternalProcessor gRPC servicer.
Tests drive the servicer with synthetic ProcessingRequest streams and
assert on:

    - the gRPC response shape (HeadersResponse, BodyResponse with
      streamed_response, ProcessingResponse oneof case)
    - the side effects on PublishService (publish_request_body /
      publish_response_body / publish_response_headers — i.e., per-message
      Kinesis logging via the existing logger.py contract)

Auth is NOT tested here — Envoy's Lua filter calls /authorise before
ext_proc sees the request, so by the time the servicer receives
request_headers the Authorization is already swapped. There's no auth
code in the servicer.
"""

from __future__ import annotations

from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as ep_pb

from portunus.relay.extproc import ExtProcRelayServicer

# ---------------------------------------------------------------------------
# Helpers — build ProcessingRequest streams without touching internals
# ---------------------------------------------------------------------------


def _hv(key: str, value: str) -> base_pb2.HeaderValue:
    return base_pb2.HeaderValue(key=key, raw_value=value.encode("utf-8"))


def _request_headers(
    *,
    request_id: str = "req-abc",
    path: str = "/v1/realtime",
    target_host: str = "api.openai.com",
) -> ep_pb.ProcessingRequest:
    headers = [
        _hv(":path", path),
        _hv(":method", "GET"),
        _hv(":authority", target_host),
        _hv("x-request-id", request_id),
        _hv("upgrade", "websocket"),
        _hv("connection", "upgrade"),
        _hv("sec-websocket-version", "13"),
        _hv("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ]
    return ep_pb.ProcessingRequest(
        request_headers=ep_pb.HttpHeaders(
            headers=base_pb2.HeaderMap(headers=headers),
            end_of_stream=False,
        )
    )


def _response_headers(
    *,
    status: str = "101",
    extensions: str | None = None,
) -> ep_pb.ProcessingRequest:
    headers = [_hv(":status", status)]
    if extensions:
        headers.append(_hv("sec-websocket-extensions", extensions))
    return ep_pb.ProcessingRequest(
        response_headers=ep_pb.HttpHeaders(
            headers=base_pb2.HeaderMap(headers=headers),
            end_of_stream=False,
        )
    )


def _body(direction: str, body: bytes, *, end: bool = False) -> ep_pb.ProcessingRequest:
    field = "request_body" if direction == "client_to_upstream" else "response_body"
    return ep_pb.ProcessingRequest(
        **{field: ep_pb.HttpBody(body=body, end_of_stream=end)}
    )


def _build_text_frame(text: str, *, mask: bool) -> bytes:
    from wsproto.connection import Connection, ConnectionType
    from wsproto.events import TextMessage

    conn = Connection(ConnectionType.CLIENT if mask else ConnectionType.SERVER)
    return conn.send(TextMessage(text, message_finished=True))


def _build_binary_frame(data: bytes, *, mask: bool) -> bytes:
    from wsproto.connection import Connection, ConnectionType
    from wsproto.events import BytesMessage

    conn = Connection(ConnectionType.CLIENT if mask else ConnectionType.SERVER)
    return conn.send(BytesMessage(data, message_finished=True))


def _build_close_frame(code: int, reason: str, *, mask: bool) -> bytes:
    from wsproto.connection import Connection, ConnectionType
    from wsproto.events import CloseConnection

    conn = Connection(ConnectionType.CLIENT if mask else ConnectionType.SERVER)
    return conn.send(CloseConnection(code=code, reason=reason))


async def _aiter(
    items: list[ep_pb.ProcessingRequest],
) -> AsyncIterator[ep_pb.ProcessingRequest]:
    for item in items:
        yield item


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def publish_service() -> AsyncMock:
    svc = AsyncMock()
    svc.publish_request_headers = AsyncMock(return_value=True)
    svc.publish_response_headers = AsyncMock(return_value=True)
    svc.publish_request_body = AsyncMock(return_value=True)
    svc.publish_response_body = AsyncMock(return_value=True)
    return svc


@pytest.fixture
def servicer(publish_service) -> ExtProcRelayServicer:
    return ExtProcRelayServicer(publish_service=publish_service)


async def _drive(
    servicer: ExtProcRelayServicer, requests: list[ep_pb.ProcessingRequest]
) -> list[ep_pb.ProcessingResponse]:
    return [
        resp async for resp in servicer.Process(_aiter(requests), context=MagicMock())
    ]


# ---------------------------------------------------------------------------
# Frame observability
# ---------------------------------------------------------------------------


class TestFrameObservability:
    @pytest.mark.asyncio
    async def test_text_frame_from_client_logged_to_request_body_stream(
        self, servicer, publish_service
    ):
        frame = _build_text_frame("hello", mask=True)
        await _drive(
            servicer,
            [
                _request_headers(),
                _response_headers(),
                _body("client_to_upstream", frame),
            ],
        )
        assert publish_service.publish_request_body.await_count == 1
        published = publish_service.publish_request_body.await_args.kwargs["body_bytes"]
        assert b"hello" in published

    @pytest.mark.asyncio
    async def test_binary_frame_from_upstream_logged_to_response_body_stream(
        self, servicer, publish_service
    ):
        payload = bytes(range(256))
        frame = _build_binary_frame(payload, mask=False)
        await _drive(
            servicer,
            [
                _request_headers(),
                _response_headers(),
                _body("upstream_to_client", frame),
            ],
        )
        assert publish_service.publish_response_body.await_count == 1
        published = publish_service.publish_response_body.await_args.kwargs[
            "body_bytes"
        ]
        assert payload == published

    @pytest.mark.asyncio
    async def test_frame_split_across_two_chunks_reassembled_to_one_publish(
        self, servicer, publish_service
    ):
        """A WS frame split across multiple ext_proc body chunks is logged once."""
        frame = _build_text_frame("split-message", mask=True)
        midpoint = len(frame) // 2
        await _drive(
            servicer,
            [
                _request_headers(),
                _response_headers(),
                _body("client_to_upstream", frame[:midpoint]),
                _body("client_to_upstream", frame[midpoint:]),
            ],
        )
        assert publish_service.publish_request_body.await_count == 1
        body = publish_service.publish_request_body.await_args.kwargs["body_bytes"]
        assert b"split-message" in body

    @pytest.mark.asyncio
    async def test_compression_negotiated_messages_decoded_before_publish(
        self, servicer, publish_service
    ):
        """Decompress permessage-deflate frames before publish.

        Kinesis sees the plaintext, not RSV1-flagged compressed bytes
        (which is what aisitok / Glue expect from the legacy relay shape).
        """
        from wsproto.connection import Connection, ConnectionType
        from wsproto.events import TextMessage
        from wsproto.extensions import PerMessageDeflate

        ext = PerMessageDeflate()
        ext.finalize("permessage-deflate")
        sender = Connection(ConnectionType.CLIENT, extensions=[ext])
        frame = sender.send(TextMessage("compress this please", message_finished=True))

        await _drive(
            servicer,
            [
                _request_headers(),
                _response_headers(extensions="permessage-deflate"),
                _body("client_to_upstream", frame),
            ],
        )

        published = publish_service.publish_request_body.await_args.kwargs["body_bytes"]
        assert b"compress this please" in published


# ---------------------------------------------------------------------------
# Pass-through (we observe but do NOT mutate body bytes)
# ---------------------------------------------------------------------------


class TestPassThrough:
    @pytest.mark.asyncio
    async def test_body_bytes_returned_unchanged_to_envoy(self, servicer):
        """Body bytes round-trip unmodified through the servicer.

        Envoy does the actual proxying; the servicer is observe-only on
        the body. Mutating bytes here would corrupt the WS stream.
        """
        frame = _build_text_frame("noop", mask=True)
        responses = await _drive(
            servicer,
            [
                _request_headers(),
                _response_headers(),
                _body("client_to_upstream", frame),
            ],
        )
        body_responses = [
            r for r in responses if r.WhichOneof("response") == "request_body"
        ]
        assert len(body_responses) == 1
        echoed = body_responses[
            0
        ].request_body.response.body_mutation.streamed_response.body
        assert echoed == frame


# ---------------------------------------------------------------------------
# Lifecycle (summary at close)
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_summary_published_when_stream_ends(self, servicer, publish_service):
        await _drive(servicer, [_request_headers(), _response_headers()])
        summary_calls = [
            call
            for call in publish_service.publish_response_headers.await_args_list
            if call.kwargs.get("headers", {}).get("x-ws-type") == "websocket-summary"
        ]
        assert len(summary_calls) == 1, (
            f"summary publish must fire once on stream end "
            f"(saw publish_response_headers calls: "
            f"{publish_service.publish_response_headers.await_args_list})"
        )

    @pytest.mark.asyncio
    async def test_close_frame_recorded_in_summary(self, servicer, publish_service):
        close = _build_close_frame(1001, "going away", mask=True)
        await _drive(
            servicer,
            [
                _request_headers(),
                _response_headers(),
                _body("client_to_upstream", close),
            ],
        )
        summary_calls = [
            call
            for call in publish_service.publish_response_headers.await_args_list
            if call.kwargs.get("headers", {}).get("x-ws-type") == "websocket-summary"
        ]
        assert len(summary_calls) == 1
        summary = summary_calls[0].kwargs["headers"]
        # Some indicator of the close code must be in the summary headers.
        assert any(
            "1001" in str(v) or "close" in k.lower() for k, v in summary.items()
        ), f"summary must record the close: {summary}"
