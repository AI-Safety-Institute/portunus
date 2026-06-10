"""Tests for Firehose batch publishing + record building."""

from __future__ import annotations

import json

import pytest

from portunus.services.publish_service import (
    _MAX_BATCH_RECORDS,
    PublishService,
    _chunk_records,
)


class _FakeFirehoseClient:
    def __init__(
        self, *, failed_per_call: int = 0, raise_on_call: bool = False
    ) -> None:
        self.calls: list[list[bytes]] = []
        self._failed_per_call = failed_per_call
        self._raise = raise_on_call

    async def put_record_batch(self, **kwargs) -> dict:
        if self._raise:
            raise RuntimeError("firehose unavailable")
        records = [r["Data"] for r in kwargs["Records"]]
        self.calls.append(records)
        return {"FailedPutCount": self._failed_per_call}


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
    client = _FakeFirehoseClient(failed_per_call=2)
    failed = await _service(client).put_record_batch("audit", [b"a\n", b"b\n", b"c\n"])
    assert failed == 2  # FailedPutCount surfaced to the caller


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


# --- build_* produce newline-terminated JSON --------------------------------


def test_build_metadata_returns_stream_and_newline_json(monkeypatch) -> None:
    from portunus.config import config

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
    from portunus.config import config

    monkeypatch.setattr(config.firehose, "metadata_stream_name", "")
    result = _service(_FakeFirehoseClient()).build_metadata(
        request_id="r1", timestamp="t", principal_info={}
    )
    assert result is None
