"""Tests for Firehose batch publishing + record building."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest

from portunus.config import config
from portunus.services.publish_service import (
    _MAX_BATCH_RECORDS,
    PublishService,
    _chunk_records,
)


class _FakeFirehoseClient:
    def __init__(
        self,
        *,
        failed_per_call: int = 0,
        raise_on_call: bool = False,
        fail_first_n_calls: int = 0,
        responses: list[dict] | None = None,
    ) -> None:
        self.calls: list[list[bytes]] = []
        self._failed_per_call = failed_per_call
        self._raise = raise_on_call
        # If set, the first N calls fail the last `failed_per_call` records
        # (with an ErrorCode); later calls succeed — models transient throttling.
        self._fail_first_n_calls = fail_first_n_calls
        self._responses = list(responses or [])

    async def put_record_batch(self, **kwargs) -> dict:
        if self._raise:
            raise RuntimeError("firehose unavailable")
        records = [r["Data"] for r in kwargs["Records"]]
        self.calls.append(records)
        if self._responses:
            return self._responses.pop(0)
        call_no = len(self.calls)
        transient = self._fail_first_n_calls and call_no <= self._fail_first_n_calls
        should_fail = transient or not self._fail_first_n_calls
        n_fail = self._failed_per_call if should_fail else 0
        if n_fail == 0:
            return {
                "FailedPutCount": 0,
                "RequestResponses": [{"RecordId": "ok"} for _ in records],
            }
        # Fail the last n_fail records, marked with an ErrorCode so the service
        # can retry exactly that subset.
        n_fail = min(n_fail, len(records))
        ok = len(records) - n_fail
        responses = [{"RecordId": "ok"} for _ in range(ok)] + [
            {"ErrorCode": "ServiceUnavailableException", "ErrorMessage": "slow down"}
            for _ in range(n_fail)
        ]
        return {"FailedPutCount": n_fail, "RequestResponses": responses}


class _FakeStateService:
    def __init__(self, client: _FakeFirehoseClient) -> None:
        self.client = client

    async def get_firehose_client(self) -> _FakeFirehoseClient:
        return self.client


def _service(client: _FakeFirehoseClient) -> PublishService:
    return PublishService(state_service=_FakeStateService(client))  # type: ignore[arg-type]


# --- _chunk_records ---------------------------------------------------------


def test_chunk_records_splits_at_500_record_cap() -> None:
    chunks = _chunk_records([b"x"] * (_MAX_BATCH_RECORDS + 50))
    assert [len(c) for c in chunks] == [_MAX_BATCH_RECORDS, 50]


def test_chunk_records_splits_at_4mib_byte_cap() -> None:
    big = b"x" * (3 * 1024 * 1024)  # 3 MiB each → only one fits per 4 MiB batch
    chunks = _chunk_records([big, big, big])
    assert [len(c) for c in chunks] == [1, 1, 1]


def test_chunk_records_empty() -> None:
    assert _chunk_records([]) == []


# --- put_record_batch -------------------------------------------------------


@pytest.mark.asyncio
async def test_put_record_batch_ships_all_records_in_one_call() -> None:
    client = _FakeFirehoseClient()
    failed = await _service(client).put_record_batch("audit", [b"a\n", b"b\n", b"c\n"])
    assert failed == 0
    assert client.calls == [[b"a\n", b"b\n", b"c\n"]]


@pytest.mark.asyncio
async def test_put_record_batch_reports_partial_failures() -> None:
    # Persistent failure: 2 records fail on every attempt, incl. the retry.
    client = _FakeFirehoseClient(failed_per_call=2)
    failed = await _service(client).put_record_batch("audit", [b"a\n", b"b\n", b"c\n"])
    assert failed == 2
    # First call (3 records) + retry of the failed subset (2 records).
    assert [len(c) for c in client.calls] == [3, 2]


@pytest.mark.asyncio
async def test_put_record_batch_retries_failed_subset_and_recovers() -> None:
    # Transient: the last 2 records fail on the first call only; the retry
    # recovers them and ships only the failed subset, not the whole chunk.
    client = _FakeFirehoseClient(failed_per_call=2, fail_first_n_calls=1)
    failed = await _service(client).put_record_batch("audit", [b"a\n", b"b\n", b"c\n"])
    assert failed == 0
    assert [len(c) for c in client.calls] == [3, 2]
    # The retry carried exactly the two records that had an ErrorCode (b, c).
    assert client.calls[1] == [b"b\n", b"c\n"]


@pytest.mark.asyncio
async def test_failed_batch_yields_before_retry_without_blocking_other_work(
    monkeypatch,
):
    waiting, release = asyncio.Event(), asyncio.Event()

    async def pause(delay):
        assert 0.5 <= delay <= 1.5
        waiting.set()
        await release.wait()

    monkeypatch.setattr(asyncio, "sleep", pause)
    client = _FakeFirehoseClient(failed_per_call=1, fail_first_n_calls=1)
    task = asyncio.create_task(
        _service(client).put_record_batch("audit", [b"ok", b"retry"])
    )
    try:
        await asyncio.wait_for(waiting.wait(), timeout=0.2)
        assert client.calls == [[b"ok", b"retry"]]
        # This coroutine remains schedulable while audit publishing waits.
        assert not task.done()
        release.set()
        assert await asyncio.wait_for(task, timeout=1) == 0
        assert client.calls == [[b"ok", b"retry"], [b"retry"]]
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_put_record_batch_counts_all_as_failed_on_transport_error() -> None:
    client = _FakeFirehoseClient(raise_on_call=True)
    failed = await _service(client).put_record_batch("audit", [b"a\n", b"b\n"])
    assert failed == 2  # never raises; all records counted failed


@pytest.mark.asyncio
async def test_put_record_batch_splits_oversized_set_into_multiple_calls() -> None:
    client = _FakeFirehoseClient()
    records = [b"x\n"] * (_MAX_BATCH_RECORDS + 10)
    failed = await _service(client).put_record_batch("audit", records)
    assert failed == 0
    assert [len(c) for c in client.calls] == [_MAX_BATCH_RECORDS, 10]


@pytest.mark.asyncio
async def test_put_record_batch_empty_is_noop() -> None:
    client = _FakeFirehoseClient()
    assert await _service(client).put_record_batch("audit", []) == 0
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {
            "FailedPutCount": 2,
            "RequestResponses": [{"ErrorCode": "ServiceUnavailableException"}],
        },
        {
            "FailedPutCount": 2,
            "RequestResponses": [
                {"ErrorCode": "ServiceUnavailableException"},
                {"RecordId": "ok"},
                {"RecordId": "ok"},
            ],
        },
        {"FailedPutCount": 0, "RequestResponses": []},
        {"FailedPutCount": 0, "RequestResponses": [{}, {}, {}]},
    ],
)
async def test_inconsistent_firehose_response_retries_all_unconfirmed_records(response):
    records = [b"a\n", b"b\n", b"c\n"]
    client = _FakeFirehoseClient(responses=[response])

    assert await _service(client).put_record_batch("audit", records) == 0
    assert client.calls == [records, records]


@pytest.mark.asyncio
async def test_repeated_inconsistent_firehose_responses_count_all_records_as_failed():
    response = {
        "FailedPutCount": 2,
        "RequestResponses": [{"ErrorCode": "ServiceUnavailableException"}],
    }
    records = [b"a\n", b"b\n", b"c\n"]
    client = _FakeFirehoseClient(responses=[response, response])

    assert await _service(client).put_record_batch("audit", records) == len(records)
    assert client.calls == [records, records]


# --- build_* produce newline-terminated JSON --------------------------------


def test_build_metadata_returns_stream_and_newline_json(monkeypatch) -> None:
    monkeypatch.setattr(config.firehose, "metadata_stream_name", "meta-stream")
    result = _service(_FakeFirehoseClient()).build_metadata(
        request_id="r1", timestamp="2026-01-01T00:00:00Z", principal_info={}
    )
    assert result is not None
    stream, data = result
    assert stream == "meta-stream"
    assert data.endswith(b"\n")
    assert json.loads(data)["record_type"] == "metadata"


def test_build_metadata_returns_none_when_stream_unconfigured(monkeypatch) -> None:
    monkeypatch.setattr(config.firehose, "metadata_stream_name", "")
    result = _service(_FakeFirehoseClient()).build_metadata(
        request_id="r1", timestamp="t", principal_info={}
    )
    assert result is None


@pytest.mark.parametrize("direction", ["request", "response"])
def test_body_record_preserves_binary_content_and_json_line_framing(
    monkeypatch, direction
):
    monkeypatch.setattr(config.firehose, f"{direction}_body_stream_name", "body-stream")
    body = bytes(range(256)) + b"\n"
    service = _service(_FakeFirehoseClient())
    build = getattr(service, f"build_{direction}_body")
    result = build(
        request_id="quoted\nidentifier",
        body_bytes=body,
        timestamp="2026-01-01T00:00:00Z",
        chunk_id=3,
        num_chunks=0,
        final_chunk=True,
        frame_index=2,
    )
    assert result is not None
    stream, data = result
    assert stream == "body-stream"
    assert data.endswith(b"\n") and len(data.splitlines()) == 1
    record = json.loads(data)
    assert base64.b64decode(record["body"]) == body
    assert record["body_size"] == len(body)
    assert record["request_id"] == "quoted\nidentifier"
    assert record["record_type"] == f"{direction}_body"
    assert (record["chunk_id"], record["final_chunk"], record["frame_index"]) == (
        3,
        True,
        2,
    )
