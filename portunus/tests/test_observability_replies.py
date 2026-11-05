"""Observability streams capture audit events without sending ignored replies."""

import pytest

from portunus.config import config
from tests.test_completed_stream_release import consume, headers
from tests.test_grpc_proc_servicer import _make_servicer


@pytest.mark.asyncio
@pytest.mark.parametrize("observability", [False, True])
async def test_reply_behavior_follows_the_incoming_protocol_mode(
    observability, monkeypatch
):
    monkeypatch.setattr(config.grpc, "proxy_api_key", "test-proxy-key-shhh")
    servicer, publish, queue = _make_servicer()

    async def incoming():
        for request in (headers(True, True), headers(False, True)):
            request.observability_mode = observability
            yield request

    await queue.start()
    try:
        responses = await consume(servicer, incoming())
    finally:
        assert await queue.stop() == 0
    assert len(responses) == (0 if observability else 2)
    assert publish.of_kind("request_headers") and publish.of_kind("response_headers")
    for kind in ("request_body", "response_body"):
        assert publish.of_kind(kind)[-1].payload["final_chunk"]
