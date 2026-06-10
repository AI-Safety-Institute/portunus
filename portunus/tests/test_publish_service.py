"""Tests for Firehose publishing behavior."""

from __future__ import annotations

import json

import pytest

from portunus.services.publish_service import PublishService


class _FakeFirehoseClient:
    def __init__(self) -> None:
        self.records: list[dict] = []

    async def put_record(self, **kwargs) -> None:
        self.records.append(kwargs)


class _FakeStateService:
    def __init__(self, client: _FakeFirehoseClient) -> None:
        self.client = client

    async def get_firehose_client(self) -> _FakeFirehoseClient:
        return self.client


@pytest.mark.asyncio
async def test_publish_to_firehose_terminates_json_record_with_newline() -> None:
    client = _FakeFirehoseClient()
    service = PublishService(state_service=_FakeStateService(client))  # type: ignore[arg-type]

    assert await service.publish_to_firehose(
        "audit-stream",
        {"record_type": "metadata", "value": 1},
        partition_key="request-1",
    )

    data = client.records[0]["Record"]["Data"]
    assert data.endswith(b"\n")
    assert json.loads(data) == {"record_type": "metadata", "value": 1}
