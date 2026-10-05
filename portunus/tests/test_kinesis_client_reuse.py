"""Tests that the backend reuses one Kinesis client across publishes."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest

from portunus.services.state_service import StateService


def _state_service_with_fake_kinesis() -> tuple[StateService, MagicMock, MagicMock]:
    """Return a StateService whose boto session yields a fake Kinesis client."""
    kinesis_client = MagicMock()
    lifecycle = MagicMock()

    @asynccontextmanager
    async def fake_create_client(service_name, **kwargs):
        assert service_name == "kinesis"
        lifecycle.entered(**kwargs)
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
    async def test_client_uses_tight_timeouts(self):
        # A stalled PutRecords holds the publish worker while the bounded queue
        # sheds audit, so botocore's 60 s read timeout must not apply.
        service, _, lifecycle = _state_service_with_fake_kinesis()

        await service.get_kinesis_client()

        (config,) = (kw["config"] for kw in [lifecycle.entered.call_args.kwargs])
        assert config.connect_timeout <= 2
        assert config.read_timeout <= 5

    @pytest.mark.asyncio
    async def test_close_exits_client_and_allows_recreation(self):
        service, _, lifecycle = _state_service_with_fake_kinesis()
        await service.get_kinesis_client()

        await service.close()

        assert lifecycle.exited.call_count == 1

        await service.get_kinesis_client()
        assert service.boto_session.create_client.call_count == 2

    @pytest.mark.asyncio
    async def test_close_without_client_is_a_noop(self):
        service, _, lifecycle = _state_service_with_fake_kinesis()

        await service.close()

        lifecycle.exited.assert_not_called()
