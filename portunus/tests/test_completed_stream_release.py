"""Release fully captured HTTP streams without waiting for Envoy's deferred close."""

import asyncio

import pytest
from envoy.service.ext_proc.v3 import external_processor_pb2 as pb

from portunus.config import config
from tests.test_grpc_proc_servicer import (
    _ctx_with_key,
    _http_body_message,
    _http_headers_message,
    _make_servicer,
    _process_responses,
)


@pytest.fixture(autouse=True)
def proxy_key(monkeypatch):
    monkeypatch.setattr(config.grpc, "proxy_api_key", "test-proxy-key-shhh")


def headers(request, end=False, websocket=False):
    message = _http_headers_message(
        headers={"upgrade": "websocket"}
        if request and websocket
        else ({":status": "101"} if websocket else {}),
        is_request=request,
        websocket_metadata=request and websocket,
    )
    getattr(
        message, "request_headers" if request else "response_headers"
    ).end_of_stream = end
    return message


async def consume(servicer, requests):
    return [
        message
        async for message in _process_responses(servicer, requests, _ctx_with_key())
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["headers", "bodies", "trailers"])
async def test_finished_http_releases_stream_and_keeps_both_terminal_records(ending):
    servicer, publish, queue = _make_servicer()
    messages = [headers(True, ending == "headers"), headers(False, ending == "headers")]
    if ending == "bodies":
        messages += [
            _http_body_message(body=b"request", is_request=True, end_of_stream=True),
            _http_body_message(body=b"response", is_request=False, end_of_stream=True),
        ]
    elif ending == "trailers":
        messages += [
            pb.ProcessingRequest(request_trailers=pb.HttpTrailers()),
            pb.ProcessingRequest(response_trailers=pb.HttpTrailers()),
        ]

    async def incoming():
        for message in messages:
            yield message
        await asyncio.Event().wait()  # Envoy has not closed its gRPC half.

    await queue.start()
    try:
        await asyncio.wait_for(consume(servicer, incoming()), 0.5)
    finally:
        assert await queue.stop() == 0
    assert servicer.active_stream_count == 0
    for kind in ("request_body", "response_body"):
        records = publish.of_kind(kind)
        assert records and records[-1].payload["final_chunk"]
    if ending == "trailers":
        assert publish.of_kind("request_trailers") and publish.of_kind(
            "response_trailers"
        )


@pytest.mark.asyncio
async def test_early_response_does_not_discard_remaining_request_body():
    servicer, publish, queue = _make_servicer()
    response_sent, release_request = asyncio.Event(), asyncio.Event()

    async def incoming():
        yield headers(True)
        yield headers(False, True)
        response_sent.set()
        await release_request.wait()
        yield _http_body_message(
            body=b"late upload", is_request=True, end_of_stream=True
        )
        await asyncio.Event().wait()

    await queue.start()
    task = asyncio.create_task(consume(servicer, incoming()))
    try:
        await asyncio.wait_for(response_sent.wait(), 0.5)
        assert not task.done()
        assert servicer.active_stream_count == 1
        release_request.set()
        await asyncio.wait_for(task, 0.5)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert await queue.stop() == 0
    assert (
        b"".join(item.payload["body_bytes"] for item in publish.of_kind("request_body"))
        == b"late upload"
    )


@pytest.mark.asyncio
async def test_websocket_stays_open_after_upgrade_headers():
    servicer, publish, queue = _make_servicer()
    waiting, release = asyncio.Event(), asyncio.Event()

    async def incoming():
        yield headers(True, True, True)
        yield headers(False, True, True)
        waiting.set()
        await release.wait()
        yield _http_body_message(body=b"\x81\x04echo", is_request=False)

    await queue.start()
    task = asyncio.create_task(consume(servicer, incoming()))
    try:
        await asyncio.wait_for(waiting.wait(), 0.5)
        assert not task.done()
        release.set()
        await asyncio.wait_for(task, 0.5)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert await queue.stop() == 0
    assert b"echo" in [
        item.payload["body_bytes"] for item in publish.of_kind("response_body")
    ]
    assert publish.of_kind("ws_summary")


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["headers", "body", "trailers"])
async def test_rejected_upgrade_releases_after_pre_response_request_completion(ending):
    servicer, publish, queue = _make_servicer()

    async def incoming():
        yield headers(True, end=ending == "headers", websocket=True)
        if ending != "headers":
            yield _http_body_message(
                body=b"upgrade payload", is_request=True, end_of_stream=ending == "body"
            )
        if ending == "trailers":
            yield pb.ProcessingRequest(request_trailers=pb.HttpTrailers())
        response = _http_headers_message(headers={":status": "403"}, is_request=False)
        response.response_headers.end_of_stream = True
        yield response
        await asyncio.Event().wait()

    await queue.start()
    try:
        await asyncio.wait_for(consume(servicer, incoming()), 0.5)
    finally:
        assert await queue.stop() == 0
    assert servicer.active_stream_count == 0
    assert not publish.of_kind("ws_summary")
    for kind in ("request_body", "response_body"):
        assert publish.of_kind(kind)[-1].payload["final_chunk"]
