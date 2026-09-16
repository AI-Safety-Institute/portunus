"""Resource ownership across REST application startup and shutdown."""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from portunus import app
from portunus.services.state_service import StateService


@dataclass
class AwsClient:
    closed: bool = False


@pytest.mark.asyncio
async def test_rest_shutdown_closes_pooled_aws_client(monkeypatch):
    client = AwsClient()

    @asynccontextmanager
    async def create_client(*_args, **_kwargs):
        try:
            yield client
        finally:
            client.closed = True

    state = StateService()
    monkeypatch.setattr(
        state, "boto_session", SimpleNamespace(create_client=create_client)
    )
    monkeypatch.setattr(app, "state_service", state)

    try:
        async with app.lifespan(app.portunus):
            async with state.pooled_boto_session().create_client(
                "sts",
                aws_access_key_id="test-access-key",
                aws_secret_access_key="test-secret-key",
            ):
                assert not client.closed
            assert not client.closed
        assert client.closed
    finally:
        await state.close()
