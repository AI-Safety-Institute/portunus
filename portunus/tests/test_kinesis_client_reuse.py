"""Tests that the backend reuses one Kinesis client across publishes."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from portunus.services.publish_service import PublishService
from portunus.services.state_service import StateService


def _state_service_with_fake_kinesis() -> tuple[StateService, MagicMock, MagicMock]:
    """Return a StateService whose boto session yields a fake Kinesis client."""
    kinesis_client = MagicMock()
    kinesis_client.put_record = AsyncMock(
        return_value={"ShardId": "shardId-000000000000", "SequenceNumber": "1234567890"}
    )
    lifecycle = MagicMock()

    @asynccontextmanager
    async def fake_create_client(service_name):
        assert service_name == "kinesis"
        lifecycle.entered()
        try:
            yield kinesis_client
        finally:
            lifecycle.exited()

    service = StateService()
    service.boto_session = MagicMock()
    service.boto_session.create_client = MagicMock(side_effect=fake_create_client)
    return service, kinesis_client, lifecycle


class TestKinesisClientReuse:
    """The shared Kinesis client is created once and closed on shutdown."""

    @pytest.mark.asyncio
    async def test_client_created_once_across_concurrent_calls(self):
        service, kinesis_client, lifecycle = _state_service_with_fake_kinesis()

        clients = await asyncio.gather(
            *(service.get_kinesis_client() for _ in range(8))
        )

        assert all(c is kinesis_client for c in clients)
        assert service.boto_session.create_client.call_count == 1
        assert lifecycle.entered.call_count == 1
        lifecycle.exited.assert_not_called()

    @pytest.mark.asyncio
    async def test_close_exits_client_and_allows_recreation(self):
        service, _, lifecycle = _state_service_with_fake_kinesis()
        await service.get_kinesis_client()

        await service.close_kinesis_client()

        assert lifecycle.exited.call_count == 1
        assert service.kinesis_client is None

        await service.get_kinesis_client()
        assert service.boto_session.create_client.call_count == 2

    @pytest.mark.asyncio
    async def test_close_without_client_is_a_noop(self):
        service, _, lifecycle = _state_service_with_fake_kinesis()

        await service.close_kinesis_client()

        lifecycle.exited.assert_not_called()

    @pytest.mark.asyncio
    async def test_state_shutdown_closes_shared_kinesis_client(self):
        service, _, lifecycle = _state_service_with_fake_kinesis()
        await service.get_kinesis_client()

        await service.close()
        await service.close()

        assert lifecycle.exited.call_count == 1

    @pytest.mark.asyncio
    async def test_publish_reuses_client_between_records(self):
        service, kinesis_client, lifecycle = _state_service_with_fake_kinesis()
        publish_service = PublishService(state_service=service)

        for i in range(3):
            ok = await publish_service.publish_to_kinesis_data_stream(
                "test-stream", {"record": i}, partition_key=f"key-{i}"
            )
            assert ok is True

        assert kinesis_client.put_record.await_count == 3
        assert service.boto_session.create_client.call_count == 1
        lifecycle.exited.assert_not_called()
        first_call = kinesis_client.put_record.await_args_list[0].kwargs
        assert first_call["StreamName"] == "test-stream"
        assert first_call["PartitionKey"] == "key-0"
