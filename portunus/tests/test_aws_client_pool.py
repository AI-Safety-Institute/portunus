"""Tests for the credential-keyed AWS client pool (backpressure LOW #3).

STS + Secrets Manager clients used to be rebuilt per auth cache-miss
(~200ms cold each: fresh aiohttp pool + TLS). ``StateService`` now pools
them per (service, credential set, endpoint) behind a session-like adapter
(``pooled_boto_session()``), which ``AuthService`` wires in by default.
"""

import asyncio
from typing import Any, Optional

import pytest

from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.secrets_service import SecretsService
from portunus.services.state_service import PooledBotoSession, StateService


class _FakeClient:
    def __init__(self, service: str, key_id: str) -> None:
        self.service = service
        self.key_id = key_id
        self.closed = False


class _FakeCtx:
    def __init__(self, client: _FakeClient, log: dict, enter_delay: float = 0.0):
        self.client = client
        self.log = log
        self.enter_delay = enter_delay

    async def __aenter__(self) -> _FakeClient:
        if self.enter_delay:
            await asyncio.sleep(self.enter_delay)
        self.log["created"] += 1
        return self.client

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.client.closed = True
        self.log["closed"] += 1


class _FakeBotoSession:
    def __init__(self, enter_delay: float = 0.0) -> None:
        self.log = {"created": 0, "closed": 0}
        self.enter_delay = enter_delay

    def create_client(
        self,
        service_name: str,
        *,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> _FakeCtx:
        return _FakeCtx(
            _FakeClient(service_name, aws_access_key_id), self.log, self.enter_delay
        )


def _pooled_state_service(enter_delay: float = 0.0) -> StateService:
    service = StateService()
    service.boto_session = _FakeBotoSession(enter_delay)  # type: ignore[assignment]
    return service


_CREDS = dict(
    aws_access_key_id="AKIA1",
    aws_secret_access_key="secret1",
    aws_session_token="token1",
)


@pytest.mark.asyncio
async def test_same_credentials_reuse_one_client():
    state = _pooled_state_service()
    first = await state.get_pooled_aws_client("sts", **_CREDS)
    second = await state.get_pooled_aws_client("sts", **_CREDS)
    assert first is second
    assert state.boto_session.log == {"created": 1, "closed": 0}
    await state.close()


@pytest.mark.asyncio
async def test_distinct_service_or_credentials_get_distinct_clients():
    state = _pooled_state_service()
    sts = await state.get_pooled_aws_client("sts", **_CREDS)
    secrets = await state.get_pooled_aws_client("secretsmanager", **_CREDS)
    other = await state.get_pooled_aws_client(
        "sts",
        aws_access_key_id="AKIA2",
        aws_secret_access_key="secret2",
        aws_session_token="token2",
    )
    assert len({id(sts), id(secrets), id(other)}) == 3
    assert state.boto_session.log["created"] == 3
    await state.close()


@pytest.mark.asyncio
async def test_pooled_session_adapter_reuses_and_never_closes_per_call():
    """The `async with session.create_client(...)` shape stays valid."""
    state = _pooled_state_service()
    session = state.pooled_boto_session()
    async with session.create_client("sts", **_CREDS) as first:
        pass
    async with session.create_client("sts", **_CREDS) as second:
        pass
    assert first is second
    assert state.boto_session.log == {"created": 1, "closed": 0}
    await state.close()
    assert state.boto_session.log == {"created": 1, "closed": 1}
    assert first.closed


@pytest.mark.asyncio
async def test_same_key_creation_race_shares_one_winner():
    """Concurrent first-time gets: the loser closes its client, shares the winner's."""
    state = _pooled_state_service(enter_delay=0.01)
    first, second = await asyncio.gather(
        state.get_pooled_aws_client("sts", **_CREDS),
        state.get_pooled_aws_client("sts", **_CREDS),
    )
    assert first is second
    assert state.boto_session.log["created"] == 2  # both built one...
    assert state.boto_session.log["closed"] == 1  # ...loser closed its own
    await state.close()


@pytest.mark.asyncio
async def test_lru_eviction_closes_oldest_after_grace():
    state = _pooled_state_service()
    state._CRED_CLIENT_POOL_MAX = 2  # type: ignore[misc]
    state._CRED_CLIENT_EVICT_GRACE_S = 0.0  # type: ignore[misc]

    clients = []
    for i in range(3):
        clients.append(
            await state.get_pooled_aws_client(
                "sts",
                aws_access_key_id=f"AKIA{i}",
                aws_secret_access_key=f"secret{i}",
                aws_session_token=None,
            )
        )
    await asyncio.sleep(0.05)  # let the grace-close task run
    assert clients[0].closed, "LRU-evicted client was not closed"
    assert not clients[1].closed and not clients[2].closed
    assert len(state._cred_client_pool) == 2
    await state.close()
    assert all(c.closed for c in clients)


@pytest.mark.asyncio
async def test_close_cancels_pending_retirements_and_closes_everything():
    state = _pooled_state_service()
    state._CRED_CLIENT_POOL_MAX = 1  # type: ignore[misc]
    # Long grace: the retirement is still pending when close() runs.
    state._CRED_CLIENT_EVICT_GRACE_S = 60.0  # type: ignore[misc]

    first = await state.get_pooled_aws_client("sts", **_CREDS)
    second = await state.get_pooled_aws_client(
        "sts",
        aws_access_key_id="AKIA2",
        aws_secret_access_key="secret2",
        aws_session_token=None,
    )
    await state.close()
    assert first.closed and second.closed
    assert not state._retiring_clients
    assert not state._cred_client_pool


class TestAuthServiceWiring:
    def test_default_secrets_service_uses_pooled_session(self):
        state = StateService()
        auth = AuthService(cache_service=CacheService(state_service=state))
        assert isinstance(auth.boto_session, PooledBotoSession)
        assert isinstance(auth.secrets_service.boto_session, PooledBotoSession)

    def test_injected_secrets_service_is_untouched(self):
        marker = object()

        class _StubSecrets:
            boto_session = marker

        auth = AuthService(
            secrets_service=_StubSecrets(),  # type: ignore[arg-type]
            cache_service=CacheService(state_service=StateService()),
        )
        assert auth.boto_session is marker

    def test_mock_cache_service_falls_back_to_plain_secrets_service(self):
        from unittest.mock import MagicMock

        auth = AuthService(cache_service=MagicMock())
        assert isinstance(auth.secrets_service, SecretsService)
        assert not isinstance(auth.boto_session, PooledBotoSession)
