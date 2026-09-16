"""Audit completion through the processor, queue, and Firehose serializer."""

from __future__ import annotations

import base64
import json
from typing import Any, AsyncIterator

import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2
from wsproto.connection import Connection, ConnectionType
from wsproto.events import CloseConnection, TextMessage

from portunus.config import config
from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.services.publish_queue import BoundedPublishQueue
from portunus.services.publish_service import PublishService


class _Firehose:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def put_record_batch(self, **kwargs: Any) -> dict[str, Any]:
        self.records.extend(json.loads(record["Data"]) for record in kwargs["Records"])
        return {
            "FailedPutCount": 0,
            "RequestResponses": [{"RecordId": "accepted"} for _ in kwargs["Records"]],
        }


class _State:
    def __init__(self, sink: _Firehose) -> None:
        self.sink = sink

    async def get_firehose_client(self) -> _Firehose:
        return self.sink


class _Context:
    def invocation_metadata(self) -> list[tuple[str, str]]:
        return [("x-portunus-proxy-key", "test-proxy-key")]

    async def abort(self, code: Any, details: str) -> None:
        raise AssertionError(f"unexpected abort: {code}: {details}")


def _headers(
    values: dict[str, str], *, request: bool, end: bool = False
) -> proc_pb2.ProcessingRequest:
    message = proc_pb2.HttpHeaders(
        headers=base_pb2.HeaderMap(
            headers=[base_pb2.HeaderValue(key=k, value=v) for k, v in values.items()]
        ),
        end_of_stream=end,
    )
    return proc_pb2.ProcessingRequest(
        **{"request_headers" if request else "response_headers": message}
    )


async def _capture(
    messages: list[proc_pb2.ProcessingRequest], monkeypatch: pytest.MonkeyPatch
) -> list[dict[str, Any]]:
    monkeypatch.setattr(config.grpc, "proxy_api_key", "test-proxy-key")
    for name in (
        "request_headers",
        "request_body",
        "request_trailers",
        "response_headers",
        "response_body",
        "response_trailers",
        "ws_summary",
    ):
        monkeypatch.setattr(config.firehose, f"{name}_stream_name", name)
    sink = _Firehose()
    publish = PublishService(state_service=_State(sink))  # type: ignore[arg-type]
    queue = BoundedPublishQueue(
        maxsize=100, num_workers=1, batch_sender=publish.put_record_batch
    )
    processor = PortunusProcessServicer(publish_service=publish, publish_queue=queue)

    async def requests() -> AsyncIterator[proc_pb2.ProcessingRequest]:
        for message in messages:
            yield message

    await queue.start()
    try:
        async for _ in processor.Process(requests(), _Context()):  # type: ignore[arg-type]
            pass
    finally:
        assert await queue.stop() == 0
    return sink.records


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["400", "403", "429"])
async def test_rejected_websocket_upgrade_preserves_http_error_body(
    status, monkeypatch
):
    body = b'{"error":"request rejected"}'
    records = await _capture(
        [
            _headers({"upgrade": "websocket"}, request=True),
            _headers({":status": status}, request=False),
            proc_pb2.ProcessingRequest(
                response_body=proc_pb2.HttpBody(body=body, end_of_stream=True)
            ),
        ],
        monkeypatch,
    )
    bodies = [r for r in records if r["record_type"] == "response_body"]
    assert b"".join(base64.b64decode(r["body"]) for r in bodies) == body
    assert bodies[-1]["final_chunk"] is True
    assert all(r["frame_index"] is None for r in bodies)
    assert not any(r["record_type"] == "ws_summary" for r in records)


@pytest.mark.asyncio
@pytest.mark.parametrize("request_end", ["headers", "body", "trailers"])
async def test_rejected_upgrade_preserves_request_completion(request_end, monkeypatch):
    messages = [
        _headers({"upgrade": "websocket"}, request=True, end=request_end == "headers")
    ]
    body = b"" if request_end == "headers" else b"hello"
    if request_end != "headers":
        messages.append(
            proc_pb2.ProcessingRequest(
                request_body=proc_pb2.HttpBody(
                    body=body, end_of_stream=request_end == "body"
                )
            )
        )
    if request_end == "trailers":
        messages.append(
            proc_pb2.ProcessingRequest(request_trailers=proc_pb2.HttpTrailers())
        )
    messages.append(_headers({":status": "403"}, request=False, end=True))

    records = await _capture(messages, monkeypatch)

    bodies = [r for r in records if r["record_type"] == "request_body"]
    assert bodies
    assert b"".join(base64.b64decode(r["body"]) for r in bodies) == body
    assert sum(r["final_chunk"] for r in bodies) == 1
    assert bodies[-1]["final_chunk"] is True
    assert all(r["frame_index"] is None for r in bodies)
    assert not any(r["record_type"] == "ws_summary" for r in records)


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["request", "response"])
async def test_http_trailers_complete_the_body(direction, monkeypatch):
    records = await _capture(
        [
            _headers({}, request=True),
            proc_pb2.ProcessingRequest(
                **{f"{direction}_body": proc_pb2.HttpBody(body=b"complete")}
            ),
            proc_pb2.ProcessingRequest(
                **{f"{direction}_trailers": proc_pb2.HttpTrailers()}
            ),
        ],
        monkeypatch,
    )
    bodies = [r for r in records if r["record_type"] == f"{direction}_body"]
    assert b"".join(base64.b64decode(r["body"]) for r in bodies) == b"complete"
    assert sum(r["final_chunk"] for r in bodies) == 1
    assert bodies[-1]["final_chunk"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["request", "response"])
async def test_headers_only_http_message_records_a_complete_empty_body(
    direction, monkeypatch
):
    records = await _capture(
        [_headers({}, request=direction == "request", end=True)], monkeypatch
    )
    bodies = [r for r in records if r["record_type"] == f"{direction}_body"]
    assert len(bodies) == 1
    assert bodies[0]["body"] == ""
    assert bodies[0]["final_chunk"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("termination", ["disconnect", "close", "partial_frame"])
async def test_interrupted_websocket_message_records_captured_bytes_as_truncated(
    termination, monkeypatch
):
    sender = Connection(ConnectionType.SERVER)
    if termination == "partial_frame":
        wire = sender.send(TextMessage(data="partial-tail"))[:-5]
    else:
        wire = sender.send(TextMessage(data="partial", message_finished=False))
        if termination == "close":
            wire += sender.send(CloseConnection(code=1000))
    records = await _capture(
        [
            _headers({"upgrade": "websocket"}, request=True),
            _headers({":status": "101"}, request=False),
            proc_pb2.ProcessingRequest(response_body=proc_pb2.HttpBody(body=wire)),
        ],
        monkeypatch,
    )
    bodies = [r for r in records if r["record_type"] == "response_body"]
    assert bodies
    assert base64.b64decode(bodies[0]["body"]) == b"partial"
    assert bodies[0]["truncated"] is True
    summary = next(r for r in records if r["record_type"] == "ws_summary")
    assert summary["truncated_server_frames"] == 1
    assert summary["server_text_frames"] == 1
    assert summary["server_close_frames"] == int(termination == "close")
    assert summary["close_code"] == (1000 if termination == "close" else None)


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("cut", [1, 2])
@pytest.mark.parametrize("complete_first", [False, True])
async def test_partial_websocket_header_marks_capture_incomplete_without_a_message(
    direction, cut, complete_first, monkeypatch
):
    sender = Connection(
        ConnectionType.CLIENT if direction == "request" else ConnectionType.SERVER
    )
    wire = sender.send(TextMessage(data="complete")) if complete_first else b""
    wire += sender.send(TextMessage(data="hello"))[:cut]
    records = await _capture(
        [
            _headers({"upgrade": "websocket"}, request=True),
            _headers({":status": "101"}, request=False),
            proc_pb2.ProcessingRequest(
                **{f"{direction}_body": proc_pb2.HttpBody(body=wire)}
            ),
        ],
        monkeypatch,
    )

    bodies = [r for r in records if r["record_type"] == f"{direction}_body"]
    assert [base64.b64decode(r["body"]) for r in bodies] == (
        [b"complete"] if complete_first else []
    )
    summary = next(r for r in records if r["record_type"] == "ws_summary")
    peer = "client" if direction == "request" else "server"
    assert summary[f"truncated_{peer}_frames"] == 1
    assert summary[f"{peer}_text_frames"] == int(complete_first)
    assert summary[f"{peer}_close_frames"] == 0
    assert summary["close_code"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["request", "response"])
async def test_unconfirmed_upgrade_accounts_for_buffered_capture_at_disconnect(
    direction, monkeypatch
):
    sender = Connection(
        ConnectionType.CLIENT if direction == "request" else ConnectionType.SERVER
    )
    records = await _capture(
        [
            _headers({"upgrade": "websocket"}, request=True),
            proc_pb2.ProcessingRequest(
                **{
                    f"{direction}_body": proc_pb2.HttpBody(
                        body=sender.send(TextMessage(data="hello"))
                    )
                }
            ),
        ],
        monkeypatch,
    )

    assert not any(r["record_type"] == f"{direction}_body" for r in records)
    summary = next(r for r in records if r["record_type"] == "ws_summary")
    peer = "client" if direction == "request" else "server"
    assert summary[f"truncated_{peer}_frames"] == 1
    assert summary[f"{peer}_text_frames"] == 0
    assert summary[f"{peer}_close_frames"] == 0
    assert summary["close_code"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("cap_direction", ["request", "response"])
@pytest.mark.parametrize("other_capture", ["none", "buffered", "after_cap"])
async def test_rejected_upgrade_keeps_cap_loss_visible_in_http_body_records(
    cap_direction, other_capture, monkeypatch
):
    monkeypatch.setattr("portunus.grpc.proc_servicer._PRE_101_MAX_BYTES", 4)
    other_direction = "response" if cap_direction == "request" else "request"
    messages = [_headers({"upgrade": "websocket"}, request=True)]
    other_body = proc_pb2.ProcessingRequest(
        **{f"{other_direction}_body": proc_pb2.HttpBody(body=b"x")}
    )
    if other_capture == "buffered":
        messages.append(other_body)
    messages.append(
        proc_pb2.ProcessingRequest(
            **{f"{cap_direction}_body": proc_pb2.HttpBody(body=b"hello")}
        )
    )
    if other_capture == "after_cap":
        messages.append(other_body)
    messages.append(_headers({":status": "403"}, request=False))
    for direction in ("request", "response"):
        messages.append(
            proc_pb2.ProcessingRequest(
                **{
                    f"{direction}_body": proc_pb2.HttpBody(
                        body=b"tail", end_of_stream=True
                    )
                }
            )
        )

    records = await _capture(messages, monkeypatch)

    for direction in ("request", "response"):
        bodies = [r for r in records if r["record_type"] == f"{direction}_body"]
        assert b"".join(base64.b64decode(r["body"]) for r in bodies) == b"tail"
        lost_capture = direction == cap_direction or other_capture != "none"
        assert sum(r["truncated"] for r in bodies) == int(lost_capture)
        assert bodies[-1]["final_chunk"] is True
        assert all(r["frame_index"] is None for r in bodies)
    assert not any(r["record_type"] == "ws_summary" for r in records)
