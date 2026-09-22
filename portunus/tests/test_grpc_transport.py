"""Exercise real gRPC stream replies, completion, identity and cancellation."""

import asyncio
from contextlib import asynccontextmanager

import grpc
import pytest
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as wire

from portunus.config import config
from tests.test_grpc_proc_servicer import (
    _PROXY_KEY,
    _http_body_message,
    _http_headers_message,
    _make_servicer,
)


@asynccontextmanager
async def running(monkeypatch):
    monkeypatch.setattr(config.grpc, "proxy_api_key", _PROXY_KEY)
    servicer, publish, queue = _make_servicer()
    await queue.start()
    server = grpc.aio.server()
    wire.add_ExternalProcessorServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    try:
        yield wire.ExternalProcessorStub(channel), servicer, publish, queue
    finally:
        await channel.close()
        await server.stop(None)
        await queue.stop()


def headers(request_side, *, observe, websocket=False):
    values = (
        {":method": "GET"}
        if request_side
        else {":status": "101" if websocket else "200"}
    )
    if websocket:
        values["upgrade"] = "websocket"
    message = _http_headers_message(
        headers=values, is_request=request_side, request_id="wire-test"
    )
    message.observability_mode = observe
    target = message.request_headers if request_side else message.response_headers
    target.end_of_stream = not websocket
    return message


async def until(predicate):
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(0.001)


@pytest.mark.asyncio
async def test_normal_mode_replies_before_client_half_close(monkeypatch):
    async with running(monkeypatch) as (stub, servicer, publish, queue):
        call = stub.Process(metadata=[("x-portunus-proxy-key", _PROXY_KEY)])
        await call.write(headers(True, observe=False))
        first = await asyncio.wait_for(call.read(), 2)
        assert first.HasField("request_headers")
        await call.write(headers(False, observe=False))
        second = await asyncio.wait_for(call.read(), 2)
        assert second.HasField("response_headers")
        assert await asyncio.wait_for(call.read(), 2) is grpc.aio.EOF
        assert servicer.active_stream_count == 0


@pytest.mark.asyncio
async def test_observation_captures_both_halves_and_completes_without_half_close(
    monkeypatch,
):
    async with running(monkeypatch) as (stub, servicer, publish, queue):
        call = stub.Process(metadata=[("x-portunus-proxy-key", _PROXY_KEY)])
        await call.write(headers(True, observe=True))
        await call.write(headers(False, observe=True))
        assert await asyncio.wait_for(call.read(), 2) is grpc.aio.EOF
        await queue.stop()
        assert servicer.active_stream_count == 0
        assert len(publish.of_kind("request_headers")) == 1
        assert len(publish.of_kind("response_headers")) == 1
        for kind in ("request_body", "response_body"):
            assert len(publish.of_kind(kind)) == 1
            assert publish.of_kind(kind)[0].payload["final_chunk"] is True


@pytest.mark.asyncio
async def test_wrong_identity_denied_before_any_body(monkeypatch):
    async with running(monkeypatch) as (stub, servicer, publish, queue):
        call = stub.Process(metadata=[("x-portunus-proxy-key", "wrong")])
        with pytest.raises(grpc.aio.AioRpcError) as error:
            await asyncio.wait_for(call.read(), 2)
        assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED
        assert servicer.active_stream_count == 0
        assert publish.items == []


@pytest.mark.asyncio
async def test_websocket_cancellation_releases_state_and_publishes_summary(monkeypatch):
    async with running(monkeypatch) as (stub, servicer, publish, queue):
        call = stub.Process(metadata=[("x-portunus-proxy-key", _PROXY_KEY)])
        await call.write(headers(True, observe=True, websocket=True))
        await call.write(headers(False, observe=True, websocket=True))
        body = _http_body_message(body=b"\x81\x82\x00\x00\x00\x00hi", is_request=True)
        body.observability_mode = True
        await call.write(body)
        await until(lambda: bool(publish.of_kind("request_body")))
        assert servicer.active_stream_count == 1
        assert call.cancel()
        await until(lambda: servicer.active_stream_count == 0)
        await queue.stop()
        assert len(publish.of_kind("ws_summary")) == 1
        assert queue.cancelled_total == 0
        assert queue.dropped_total == 0
