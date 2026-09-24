"""Tests for Kinesis packing + publishing and record building."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest

from portunus.config import config
from portunus.services.publish_service import (
    _MAX_CALL_BYTES,
    _MAX_CALL_RECORDS,
    _PACK_MAX_RECORDS,
    _PACK_TARGET_BYTES,
    PublishService,
    _chunk_packs,
    _pack_records,
)


class _FakeKinesisClient:
    """Records each PutRecords call as its list of (Data, PartitionKey)."""

    def __init__(
        self,
        *,
        failed_per_call: int = 0,
        raise_on_call: bool = False,
        fail_first_n_calls: int = 0,
        error_code: str = "ProvisionedThroughputExceededException",
        responses: list[dict] | None = None,
    ) -> None:
        self.calls: list[list[tuple[bytes, str]]] = []
        self._failed_per_call = failed_per_call
        self._raise = raise_on_call
        # If set, the first N calls fail the last `failed_per_call` packs
        # (with an ErrorCode); later calls succeed — models transient throttling.
        self._fail_first_n_calls = fail_first_n_calls
        self._error_code = error_code
        self._responses = list(responses or [])

    def data(self, call: int) -> list[bytes]:
        return [d for d, _ in self.calls[call]]

    async def put_records(self, **kwargs) -> dict:
        if self._raise:
            raise RuntimeError("kinesis unavailable")
        records = [(r["Data"], r["PartitionKey"]) for r in kwargs["Records"]]
        self.calls.append(records)
        if self._responses:
            return self._responses.pop(0)
        call_no = len(self.calls)
        transient = self._fail_first_n_calls and call_no <= self._fail_first_n_calls
        should_fail = transient or not self._fail_first_n_calls
        n_fail = min(self._failed_per_call if should_fail else 0, len(records))
        ok = len(records) - n_fail
        responses = [
            {"SequenceNumber": "1", "ShardId": "shardId-0"} for _ in range(ok)
        ] + [
            {"ErrorCode": self._error_code, "ErrorMessage": "slow down"}
            for _ in range(n_fail)
        ]
        return {"FailedRecordCount": n_fail, "Records": responses}


class _FakeStateService:
    def __init__(self, client: _FakeKinesisClient) -> None:
        self.client = client

    async def get_kinesis_client(self) -> _FakeKinesisClient:
        return self.client


def _service(client: _FakeKinesisClient) -> PublishService:
    return PublishService(state_service=_FakeStateService(client))  # type: ignore[arg-type]


def _big(n: int) -> list[bytes]:
    """Records each just over half the pack target, so one fits per pack."""
    return [b"x" * (_PACK_TARGET_BYTES // 2 + 1) + b"\n" for _ in range(n)]


# --- _pack_records / _chunk_packs -------------------------------------------


def test_pack_records_concatenates_small_records_into_one_pack() -> None:
    assert _pack_records([b"a\n", b"b\n", b"c\n"]) == [(b"a\nb\nc\n", 3)]


def test_pack_records_terminates_bare_records() -> None:
    # De-aggregation splits on newlines; a bare record would merge with the next.
    assert _pack_records([b"a", b"b\n"]) == [(b"a\nb\n", 2)]


def test_pack_records_caps_sub_records_per_pack() -> None:
    # Firehose RecordDeAggregation handles at most 500 sub-records per record.
    packs = _pack_records([b"x\n"] * (_PACK_MAX_RECORDS + 1))
    assert [n for _, n in packs] == [_PACK_MAX_RECORDS, 1]


def test_pack_records_caps_pack_bytes() -> None:
    packs = _pack_records(_big(3))
    assert [n for _, n in packs] == [1, 1, 1]
    assert all(len(d) <= _PACK_TARGET_BYTES for d, _ in packs)


def test_pack_records_gives_oversized_record_its_own_pack() -> None:
    huge = b"x" * (_PACK_TARGET_BYTES * 3) + b"\n"
    packs = _pack_records([b"a\n", huge, b"b\n"])
    assert packs == [(b"a\n", 1), (huge, 1), (b"b\n", 1)]


def test_pack_records_preserves_every_record_in_order() -> None:
    records = [f"{i}\n".encode() for i in range(1200)]
    packs = _pack_records(records)
    assert b"".join(d for d, _ in packs) == b"".join(records)
    assert sum(n for _, n in packs) == len(records)


def test_chunk_packs_splits_at_500_record_cap() -> None:
    chunks = _chunk_packs([(b"x", 1)] * (_MAX_CALL_RECORDS + 50))
    assert [len(c) for c in chunks] == [_MAX_CALL_RECORDS, 50]


def test_chunk_packs_splits_at_5mib_byte_cap() -> None:
    mib = (b"x" * (1024 * 1024 - 64), 1)  # ~1 MiB incl. partition key
    chunks = _chunk_packs([mib] * 6)
    assert [len(c) for c in chunks] == [5, 1]
    for chunk in chunks:
        assert sum(len(d) + 32 for d, _ in chunk) <= _MAX_CALL_BYTES


def test_pack_and_chunk_empty() -> None:
    assert _pack_records([]) == []
    assert _chunk_packs([]) == []


# --- put_record_batch -------------------------------------------------------


@pytest.mark.asyncio
async def test_put_record_batch_packs_records_into_one_kinesis_record() -> None:
    client = _FakeKinesisClient()
    failed = await _service(client).put_record_batch("audit", [b"a\n", b"b\n", b"c\n"])
    assert failed == 0
    assert client.data(0) == [b"a\nb\nc\n"]


@pytest.mark.asyncio
async def test_put_record_batch_uses_random_partition_keys() -> None:
    client = _FakeKinesisClient()
    await _service(client).put_record_batch("audit", _big(4))
    keys = [k for _, k in client.calls[0]]
    assert len(keys) == 4 and len(set(keys)) == 4
    assert all(len(k) == 32 for k in keys)


@pytest.mark.asyncio
async def test_put_record_batch_reports_partial_failures_in_audit_records() -> None:
    # Persistent failure: the last pack (1 audit record) fails every attempt.
    # Failure counts are in audit records, not packs: a small batch packs
    # into a single KDS record, so one failed pack loses all three.
    client = _FakeKinesisClient(failed_per_call=1)
    service = _service(client)
    failed = await service.put_record_batch("audit", [b"a\n", b"b\n", b"c\n"])
    assert failed == 3
    assert [len(c) for c in client.calls] == [1, 1]
    assert service.throttled_total == 6  # both attempts throttled


@pytest.mark.asyncio
async def test_put_record_batch_retries_failed_packs_under_fresh_keys() -> None:
    # Transient: the last 2 packs fail on the first call only; the retry ships
    # only those packs, each under a new partition key (a re-key lands it on
    # a different shard if the first was hot).
    client = _FakeKinesisClient(failed_per_call=2, fail_first_n_calls=1)
    records = _big(3)
    failed = await _service(client).put_record_batch("audit", records)
    assert failed == 0
    assert [len(c) for c in client.calls] == [3, 2]
    assert client.data(1) == records[1:]
    first_keys = {k for _, k in client.calls[0]}
    assert not first_keys & {k for _, k in client.calls[1]}


@pytest.mark.asyncio
async def test_non_throttle_errors_count_as_put_errors_not_throttles() -> None:
    client = _FakeKinesisClient(
        failed_per_call=1, error_code="InternalFailure", fail_first_n_calls=1
    )
    service = _service(client)
    assert await service.put_record_batch("audit", [b"a\n"]) == 0
    assert service.throttled_total == 0


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
    client = _FakeKinesisClient(failed_per_call=1, fail_first_n_calls=1)
    records = _big(2)
    task = asyncio.create_task(_service(client).put_record_batch("audit", records))
    try:
        await asyncio.wait_for(waiting.wait(), timeout=0.2)
        assert client.data(0) == records
        # This coroutine remains schedulable while audit publishing waits.
        assert not task.done()
        release.set()
        assert await asyncio.wait_for(task, timeout=1) == 0
        assert client.data(1) == records[1:]
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_put_record_batch_counts_all_as_failed_on_transport_error() -> None:
    client = _FakeKinesisClient(raise_on_call=True)
    service = _service(client)
    failed = await service.put_record_batch("audit", [b"a\n", b"b\n"])
    assert failed == 2  # never raises; all records counted failed
    assert service.put_errors_total == 2


@pytest.mark.asyncio
async def test_put_record_batch_splits_large_set_into_multiple_calls() -> None:
    client = _FakeKinesisClient()
    # 45 packs of ~128 KiB is ~5.6 MiB: two PutRecords calls.
    records = _big(45)
    failed = await _service(client).put_record_batch("audit", records)
    assert failed == 0
    assert len(client.calls) == 2
    assert [d for i in range(2) for d in client.data(i)] == records


@pytest.mark.asyncio
async def test_put_record_batch_empty_is_noop() -> None:
    client = _FakeKinesisClient()
    assert await _service(client).put_record_batch("audit", []) == 0
    assert client.calls == []


_OK = {"SequenceNumber": "1", "ShardId": "shardId-0"}
_THROTTLED = {"ErrorCode": "ProvisionedThroughputExceededException"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        # Too few entries for the packs sent.
        {"FailedRecordCount": 2, "Records": [_THROTTLED]},
        # FailedRecordCount disagrees with the ErrorCodes.
        {"FailedRecordCount": 2, "Records": [_THROTTLED, _OK, _OK]},
        {"FailedRecordCount": 0, "Records": []},
        # Entries with neither SequenceNumber nor ErrorCode.
        {"FailedRecordCount": 0, "Records": [{}, {}, {}]},
        # Entries with both.
        {"FailedRecordCount": 0, "Records": [{**_OK, **_THROTTLED}] * 3},
        {"FailedRecordCount": "0", "Records": [_OK, _OK, _OK]},
    ],
)
async def test_inconsistent_kinesis_response_retries_all_unconfirmed_packs(response):
    records = _big(3)
    client = _FakeKinesisClient(responses=[response])

    assert await _service(client).put_record_batch("audit", records) == 0
    assert client.data(0) == records
    assert client.data(1) == records


@pytest.mark.asyncio
async def test_repeated_inconsistent_kinesis_responses_count_all_records_as_failed():
    response = {"FailedRecordCount": 2, "Records": [_THROTTLED]}
    records = _big(3)
    client = _FakeKinesisClient(responses=[response, response])

    assert await _service(client).put_record_batch("audit", records) == len(records)
    assert len(client.calls) == 2


# --- build_* produce newline-terminated JSON --------------------------------


def test_build_metadata_returns_stream_and_newline_json(monkeypatch) -> None:
    monkeypatch.setattr(config.firehose, "metadata_stream_name", "meta-stream")
    result = _service(_FakeKinesisClient()).build_metadata(
        request_id="r1", timestamp="2026-01-01T00:00:00Z", principal_info={}
    )
    assert result is not None
    stream, data = result
    assert stream == "meta-stream"
    assert data.endswith(b"\n")
    assert json.loads(data)["record_type"] == "metadata"


def test_build_metadata_returns_none_when_stream_unconfigured(monkeypatch) -> None:
    monkeypatch.setattr(config.firehose, "metadata_stream_name", "")
    result = _service(_FakeKinesisClient()).build_metadata(
        request_id="r1", timestamp="t", principal_info={}
    )
    assert result is None


@pytest.mark.parametrize("direction", ["request", "response"])
def test_body_record_preserves_binary_content_and_json_line_framing(
    monkeypatch, direction
):
    monkeypatch.setattr(config.firehose, f"{direction}_body_stream_name", "body-stream")
    body = bytes(range(256)) + b"\n"
    service = _service(_FakeKinesisClient())
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
