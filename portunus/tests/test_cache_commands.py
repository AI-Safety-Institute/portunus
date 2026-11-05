"""Cache operations run straight through the Redis command boundary."""

from collections import deque
from typing import Any

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from fakeredis import FakeAsyncRedis
from redis.exceptions import ConnectionError

from portunus.config import config
from portunus.models import AuthResult, PrincipalInfo
from portunus.services.cache_service import CacheError, CacheService
from portunus.services.state_service import StateService, _build_redis_pool


class RedisEndpoint(FakeAsyncRedis):
    def __init__(self) -> None:
        super().__init__(decode_responses=True)
        self.commands: list[str] = []
        self.failures: dict[str, deque[Exception]] = {}

    async def execute_command(self, name: str, *args: Any, **kwargs: Any) -> Any:
        self.commands.append(name)
        failures = self.failures.get(name)
        if failures:
            raise failures.popleft()
        return await super().execute_command(name, *args, **kwargs)


@pytest_asyncio.fixture
async def cache_endpoint():
    endpoint = RedisEndpoint()
    state = StateService()
    state.redis_client = endpoint
    try:
        yield CacheService(state_service=state), endpoint
    finally:
        await state.close_redis_client()
        await state.close()


def auth_result() -> AuthResult:
    return AuthResult(api_key="synthetic-key", principal_info=PrincipalInfo())


def pool_wait_expired() -> ConnectionError:
    """The error redis-py's ``BlockingConnectionPool`` raises when its wait expires.

    ``BlockingConnectionPool.get_connection`` does
    ``raise ConnectionError("No connection available.") from err`` where ``err``
    is the wait's ``TimeoutError`` (redis-py 5.3.1).
    """
    error = ConnectionError("No connection available.")
    error.__cause__ = TimeoutError()
    return error


@pytest.mark.asyncio
async def test_cache_round_trip_uses_only_data_commands(cache_endpoint):
    cache, endpoint = cache_endpoint
    assert await cache.cache_auth_result("payload", "example.com", auth_result(), 30)
    hit = await cache.get_cached_auth_result("payload", "example.com")
    assert hit is not None and hit.api_key == "synthetic-key"
    assert await cache.flush_all()
    assert await cache.get_cached_auth_result("payload", "example.com") is None
    assert endpoint.commands == ["PSETEX", "GET", "FLUSHDB", "GET"]


@pytest.mark.asyncio
async def test_connection_failure_is_reported_and_a_later_lookup_can_recover(
    cache_endpoint,
):
    cache, endpoint = cache_endpoint
    assert await cache.cache_auth_result("payload", "example.com", auth_result(), 30)
    endpoint.commands.clear()
    endpoint.failures["GET"] = deque([ConnectionError("Disconnected")])

    with pytest.raises(CacheError):
        await cache.get_cached_auth_result("payload", "example.com")
    assert endpoint.commands == ["GET"]
    hit = await cache.get_cached_auth_result("payload", "example.com")
    assert hit is not None and hit.api_key == "synthetic-key"


@pytest.mark.asyncio
async def test_pool_wait_expiry_on_lookup_is_a_timeout_not_a_cache_error(
    cache_endpoint,
):
    """A lookup that could not get a pooled connection in time is a timeout.

    ``AuthService`` rejects timeouts and treats every other cache error as a
    miss, so this is what keeps a saturated pool from falling through to STS.
    """
    cache, endpoint = cache_endpoint
    endpoint.failures["GET"] = deque([pool_wait_expired()])

    with pytest.raises(TimeoutError) as exc_info:
        await cache.get_cached_auth_result("payload", "example.com")

    assert type(exc_info.value) is TimeoutError
    assert isinstance(exc_info.value.__cause__, ConnectionError)


@pytest.mark.asyncio
async def test_pool_wait_expiry_is_recognised_by_cause_not_message(cache_endpoint):
    """Only the chained ``TimeoutError`` marks a pool wait; the text does not."""
    cache, endpoint = cache_endpoint
    endpoint.failures["GET"] = deque([ConnectionError("No connection available.")])

    with pytest.raises(CacheError):
        await cache.get_cached_auth_result("payload", "example.com")


@pytest.mark.asyncio
async def test_real_pool_wait_expiry_surfaces_as_a_timeout(monkeypatch):
    """End to end through redis-py's ``BlockingConnectionPool``, not a fake."""
    monkeypatch.setattr(config.redis, "max_connections", 1)
    monkeypatch.setattr(config.redis, "pool_timeout_seconds", 0.05)
    monkeypatch.setattr(config.redis, "use_tls", False)
    pool = _build_redis_pool()
    pool._in_use_connections.add(pool.make_connection())
    state = StateService()
    state.redis_client = aioredis.Redis.from_pool(pool)
    cache = CacheService(state_service=state)
    try:
        with pytest.raises(TimeoutError) as exc_info:
            await cache.get_cached_auth_result("payload", "example.com")
    finally:
        await state.close_redis_client()

    assert type(exc_info.value) is TimeoutError
    assert isinstance(exc_info.value.__cause__, ConnectionError)


@pytest.mark.asyncio
async def test_readiness_still_probes_redis(cache_endpoint):
    cache, endpoint = cache_endpoint
    assert await cache.health_check()
    endpoint.failures["PING"] = deque([ConnectionError("Disconnected")])
    assert not await cache.health_check()
    assert await cache.health_check()
    assert endpoint.commands == ["PING", "PING", "PING"]
