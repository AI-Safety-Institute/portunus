"""Flushing the shared cache forces every subsequent request to reauthenticate."""

from __future__ import annotations

from typing import Optional

import pytest

from portunus.models import AuthResult, PrincipalInfo
from portunus.services.cache_service import CacheService
from portunus.services.state_service import StateService


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> Optional[str]:
        return self._store.get(key)

    async def psetex(self, key: str, ttl: int, value: str) -> bool:
        self._store[key] = value
        return True

    async def flushdb(self) -> bool:
        self._store.clear()
        return True


@pytest.mark.asyncio
async def test_flush_all_invalidates_every_read_path():
    state = StateService()
    state.redis_client = _FakeRedis()  # type: ignore[assignment]
    cache = CacheService(state_service=state)
    payload = "payload-abc"
    host = "api.anthropic.com"
    result = AuthResult(
        api_key="sk-compromised-key",
        signing_key=None,
        principal_info=PrincipalInfo(),
    )

    assert await cache.cache_auth_result(payload, result, target_host=host)
    hit = await cache.get_cached_auth_result(payload, host)
    assert hit is not None and hit.api_key == "sk-compromised-key"

    assert await cache.flush_all()

    # The flushed key must be gone from EVERY layer a read consults.
    assert await cache.get_cached_auth_result(payload, host) is None
