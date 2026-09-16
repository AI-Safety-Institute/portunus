"""Cache operations use bounded retries at the Redis command boundary."""

import asyncio
from collections import deque
from typing import Any

import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.exceptions import ConnectionError, MaxConnectionsError

from portunus.models import AuthResult, PrincipalInfo
from portunus.services.cache_service import CacheError, CacheService
from portunus.services.state_service import StateService


class RedisEndpoint(FakeAsyncRedis):
    def __init__(self) -> None:
        super().__init__(decode_responses=True)
        self.commands: list[str] = []
        self.expiry_requests_ms: list[int] = []
        self.failures: dict[str, deque[Exception]] = {}
        self.rejected = asyncio.Event()
        self.rejection_delay = 0.0

    async def execute_command(self, name: str, *args: Any, **kwargs: Any) -> Any:
        self.commands.append(name)
        if name == "PSETEX":
            self.expiry_requests_ms.append(args[1])
        failures = self.failures.get(name)
        if failures:
            if self.rejection_delay:
                await asyncio.sleep(self.rejection_delay)
            self.rejected.set()
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
    return AuthResult(
        api_key="synthetic-key", signing_key=None, principal_info=PrincipalInfo()
    )


@pytest.mark.asyncio
async def test_cache_round_trip_uses_only_data_commands(cache_endpoint):
    cache, endpoint = cache_endpoint
    assert await cache.cache_auth_result("payload", auth_result(), 30, "example.com")
    hit = await cache.get_cached_auth_result("payload", "example.com")
    assert hit is not None and hit.api_key == "synthetic-key"
    assert await cache.flush_all()
    assert await cache.get_cached_auth_result("payload", "example.com") is None
    assert endpoint.commands == ["PSETEX", "GET", "FLUSHDB", "GET"]


@pytest.mark.parametrize("command", ["GET", "PSETEX", "FLUSHDB"])
@pytest.mark.parametrize(
    "failure",
    [MaxConnectionsError("Pool occupied"), ConnectionError("Too many connections")],
)
@pytest.mark.asyncio
async def test_cache_command_recovers_after_pool_contention(
    cache_endpoint, command, failure
):
    cache, endpoint = cache_endpoint
    assert await cache.cache_auth_result("payload", auth_result(), 30, "example.com")
    endpoint.commands.clear()
    endpoint.failures[command] = deque([failure])

    if command == "GET":
        hit = await cache.get_cached_auth_result("payload", "example.com")
        assert hit is not None and hit.api_key == "synthetic-key"
    elif command == "PSETEX":
        assert await cache.cache_auth_result("other", auth_result(), 30, "example.com")
        assert await cache.get_cached_auth_result("other", "example.com") is not None
    else:
        assert await cache.flush_all()
        assert await cache.get_cached_auth_result("payload", "example.com") is None

    assert endpoint.commands[:2] == [command, command]


@pytest.mark.asyncio
async def test_connection_failure_is_reported_and_a_later_lookup_can_recover(
    cache_endpoint,
):
    cache, endpoint = cache_endpoint
    assert await cache.cache_auth_result("payload", auth_result(), 30, "example.com")
    endpoint.commands.clear()
    endpoint.failures["GET"] = deque([ConnectionError("Disconnected")])

    with pytest.raises(CacheError):
        await cache.get_cached_auth_result("payload", "example.com")
    assert endpoint.commands == ["GET"]
    hit = await cache.get_cached_auth_result("payload", "example.com")
    assert hit is not None and hit.api_key == "synthetic-key"


@pytest.mark.asyncio
async def test_cancelling_a_contended_lookup_stops_retrying(cache_endpoint):
    cache, endpoint = cache_endpoint
    endpoint.failures["GET"] = deque([MaxConnectionsError("Pool occupied")])
    lookup = asyncio.create_task(cache.get_cached_auth_result("payload", "example.com"))
    await endpoint.rejected.wait()
    lookup.cancel()
    with pytest.raises(asyncio.CancelledError):
        await lookup
    assert endpoint.commands == ["GET"]


@pytest.mark.asyncio
async def test_readiness_still_probes_redis(cache_endpoint):
    cache, endpoint = cache_endpoint
    assert await cache.health_check()
    endpoint.failures["PING"] = deque([ConnectionError("Disconnected")])
    assert not await cache.health_check()
    assert await cache.health_check()
    assert endpoint.commands == ["PING", "PING", "PING"]


@pytest.mark.asyncio
async def test_cache_write_does_not_restart_its_lifetime_after_waiting(cache_endpoint):
    cache, endpoint = cache_endpoint
    endpoint.failures["PSETEX"] = deque([MaxConnectionsError("Pool occupied")])
    endpoint.rejection_delay = 1.1
    assert not await cache.cache_auth_result("payload", auth_result(), 1, "example.com")
    assert await cache.get_cached_auth_result("payload", "example.com") is None


@pytest.mark.asyncio
async def test_successful_cache_retry_keeps_only_the_remaining_lifetime(cache_endpoint):
    cache, endpoint = cache_endpoint
    lifetime = 3
    endpoint.failures["PSETEX"] = deque([MaxConnectionsError("Pool occupied")])
    endpoint.rejection_delay = 0.5

    assert await cache.cache_auth_result(
        "payload", auth_result(), lifetime, "example.com"
    )
    remaining_ms = endpoint.expiry_requests_ms[-1]
    assert 0 < remaining_ms < (lifetime - endpoint.rejection_delay) * 1000


@pytest.mark.asyncio
async def test_pool_contention_eventually_fails_without_exhausting_all_rejections(
    cache_endpoint,
):
    cache, endpoint = cache_endpoint
    endpoint.failures["GET"] = deque(
        MaxConnectionsError("Pool occupied") for _ in range(100)
    )
    async with asyncio.timeout(10):
        with pytest.raises(CacheError):
            await cache.get_cached_auth_result("payload", "example.com")
    assert endpoint.failures["GET"]
    assert endpoint.commands.count("GET") > 1
