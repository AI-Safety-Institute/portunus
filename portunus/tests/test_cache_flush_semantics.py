"""Fleet-wide flush semantics for the two-layer auth cache.

Each task keeps an in-process layer in front of shared Redis, so a flush
handled by one task cannot reach the others' memories directly. Instead,
``flush_all`` rewrites a flush token in Redis after FLUSHDB; every task
re-checks that token at most ``flush_poll_seconds`` apart and drops its
in-process layer on change. These tests pin the resulting contract: the
flushing task converges instantly, every other task within one poll
interval, and repeat reads still avoid Redis in between.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import pytest

from portunus.models import AuthResult, PrincipalInfo
from portunus.services.cache_service import CacheService

POLL_SECONDS = 0.2


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.get_calls: list[str] = []
        self.failing_keys: set[str] = set()

    async def get(self, key: str) -> Optional[str]:
        self.get_calls.append(key)
        if key in self.failing_keys:
            raise ConnectionError("injected redis failure")
        return self._store.get(key)

    async def set(self, key: str, value: str) -> bool:
        self._store[key] = value
        return True

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self._store[key] = value
        return True

    async def flushdb(self) -> bool:
        self._store.clear()
        return True


class _FakeStateService:
    def __init__(self, redis: Optional[_FakeRedis] = None) -> None:
        self._redis = redis or _FakeRedis()

    async def acquire_redis_connection(self, *_a: Any, **_k: Any) -> _FakeRedis:
        return self._redis


def _make_task(redis: _FakeRedis) -> CacheService:
    """One CacheService per fake ECS task, all sharing one Redis."""
    return CacheService(
        state_service=_FakeStateService(redis),  # type: ignore[arg-type]
        flush_poll_seconds=POLL_SECONDS,
    )


def _auth_result(api_key: str) -> AuthResult:
    return AuthResult(
        api_key=api_key,
        signing_key=None,
        principal_info=PrincipalInfo(),
    )


@pytest.mark.asyncio
async def test_flush_all_invalidates_every_read_path_on_the_flushing_task():
    redis = _FakeRedis()
    task = _make_task(redis)
    payload = "payload-abc"
    host = "api.anthropic.com"

    assert await task.cache_auth_result(
        payload, _auth_result("sk-compromised-key"), target_host=host
    )
    hit = await task.get_cached_auth_result(payload, host)
    assert hit is not None
    assert hit.api_key == "sk-compromised-key"

    assert await task.flush_all()

    # The flushing task converges instantly — no waiting on the poll interval.
    assert await task.get_cached_auth_result(payload, host) is None


@pytest.mark.asyncio
async def test_repeat_reads_are_served_from_process_memory():
    redis = _FakeRedis()
    task = _make_task(redis)
    payload = "payload-abc"

    await task.cache_auth_result(payload, _auth_result("sk-key"))
    key = task.generate_cache_key(payload)

    first = await task.get_cached_auth_result(payload)
    assert first is not None
    entry_reads_after_first = redis.get_calls.count(key)

    second = await task.get_cached_auth_result(payload)
    assert second is not None
    assert second.api_key == "sk-key"
    assert redis.get_calls.count(key) == entry_reads_after_first


@pytest.mark.asyncio
async def test_task_that_missed_the_flush_converges_within_one_poll_interval():
    redis = _FakeRedis()
    flusher = _make_task(redis)
    bystander = _make_task(redis)
    payload = "payload-abc"

    await flusher.cache_auth_result(payload, _auth_result("sk-compromised-key"))
    warmed = await bystander.get_cached_auth_result(payload)
    assert warmed is not None

    assert await flusher.flush_all()

    # Immediately after, the bystander still serves from process memory —
    # that's the mechanism whose convergence we're bounding.
    assert await bystander.get_cached_auth_result(payload) is not None

    await asyncio.sleep(POLL_SECONDS * 1.5)
    assert await bystander.get_cached_auth_result(payload) is None


@pytest.mark.asyncio
async def test_rotated_key_is_served_after_flush_convergence():
    redis = _FakeRedis()
    flusher = _make_task(redis)
    bystander = _make_task(redis)
    payload = "payload-abc"

    await flusher.cache_auth_result(payload, _auth_result("sk-old-key"))
    assert await bystander.get_cached_auth_result(payload) is not None

    assert await flusher.flush_all()
    await flusher.cache_auth_result(payload, _auth_result("sk-rotated-key"))

    await asyncio.sleep(POLL_SECONDS * 1.5)
    converged = await bystander.get_cached_auth_result(payload)
    assert converged is not None
    assert converged.api_key == "sk-rotated-key"


@pytest.mark.asyncio
async def test_flush_token_check_failure_keeps_serving_cached_entries():
    """Redis being unreachable must not blank the in-process cache.

    No flush can land while Redis is down, so there is nothing new to
    converge to.
    """
    redis = _FakeRedis()
    task = CacheService(
        state_service=_FakeStateService(redis),  # type: ignore[arg-type]
        flush_poll_seconds=0,
    )
    payload = "payload-abc"

    await task.cache_auth_result(payload, _auth_result("sk-key"))
    assert await task.get_cached_auth_result(payload) is not None

    redis.failing_keys.add("cache:flush-token")
    still_served = await task.get_cached_auth_result(payload)
    assert still_served is not None
    assert still_served.api_key == "sk-key"


@pytest.mark.asyncio
async def test_second_flush_is_detected_even_after_the_first():
    """FLUSHDB deletes the token key itself.

    The signal must not depend on a counter that restarts from the same
    value after every flush.
    """
    redis = _FakeRedis()
    flusher = _make_task(redis)
    bystander = _make_task(redis)
    payload = "payload-abc"

    await flusher.cache_auth_result(payload, _auth_result("sk-key-1"))
    assert await bystander.get_cached_auth_result(payload) is not None
    assert await flusher.flush_all()
    await asyncio.sleep(POLL_SECONDS * 1.5)
    assert await bystander.get_cached_auth_result(payload) is None

    await flusher.cache_auth_result(payload, _auth_result("sk-key-2"))
    assert await bystander.get_cached_auth_result(payload) is not None
    assert await flusher.flush_all()
    await asyncio.sleep(POLL_SECONDS * 1.5)
    assert await bystander.get_cached_auth_result(payload) is None
