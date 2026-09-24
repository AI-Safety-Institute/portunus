"""Tests for the in-process (L1) auth cache."""

import asyncio

import pytest

from portunus.models import AuthResult, PrincipalInfo
from portunus.services.local_auth_cache import LocalAuthCache


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _result(api_key: str = "sk-test") -> AuthResult:
    return AuthResult(
        api_key=api_key,
        signing_key=None,
        principal_info=PrincipalInfo(
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/s",
            account_id="123456789012",
        ),
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cache(clock: FakeClock) -> LocalAuthCache:
    return LocalAuthCache(ttl_seconds=30, stale_seconds=300, max_entries=3, clock=clock)


class TestFreshness:
    def test_fresh_within_ttl(self, cache, clock):
        cache.put("k", _result(), credential_ttl=3600)
        clock.now += 29
        assert cache.get_fresh("k") == _result()

    def test_not_fresh_after_ttl_but_stale_servable(self, cache, clock):
        cache.put("k", _result(), credential_ttl=3600)
        clock.now += 31
        assert cache.get_fresh("k") is None
        assert cache.get_stale("k") == _result()

    def test_stale_window_ends(self, cache, clock):
        cache.put("k", _result(), credential_ttl=3600)
        clock.now += 30 + 300
        assert cache.get_stale("k") is None
        assert len(cache) == 0

    def test_never_served_past_credential_expiry(self, cache, clock):
        cache.put("k", _result(), credential_ttl=10)
        clock.now += 9
        assert cache.get_fresh("k") is not None
        clock.now += 1
        assert cache.get_fresh("k") is None
        assert cache.get_stale("k") is None

    def test_expired_credentials_not_stored(self, cache):
        cache.put("k", _result(), credential_ttl=0)
        assert len(cache) == 0

    def test_no_credential_expiry_bounded_by_ttl_plus_stale(self, cache, clock):
        cache.put("k", _result(), credential_ttl=None)
        clock.now += 329
        assert cache.get_stale("k") is not None
        clock.now += 1
        assert cache.get_stale("k") is None

    def test_unsuccessful_result_not_stored(self, cache):
        cache.put("k", _result(api_key=""), credential_ttl=3600)
        assert len(cache) == 0

    def test_disabled_stores_nothing(self, clock):
        cache = LocalAuthCache(
            ttl_seconds=0, stale_seconds=300, max_entries=10, clock=clock
        )
        assert not cache.enabled
        cache.put("k", _result(), credential_ttl=3600)
        assert len(cache) == 0


class TestLru:
    def test_evicts_least_recently_used(self, cache):
        for k in ("a", "b", "c"):
            cache.put(k, _result(k), credential_ttl=3600)
        assert cache.get_fresh("a") is not None  # a is now most recent
        cache.put("d", _result("d"), credential_ttl=3600)
        assert cache.get_fresh("b") is None
        assert cache.get_fresh("a") is not None
        assert len(cache) == 3


class TestServable:
    def test_has_servable_entries(self, cache, clock):
        assert not cache.has_servable_entries()
        cache.put("k", _result(), credential_ttl=3600)
        assert cache.has_servable_entries()
        clock.now += 100  # past TTL, inside stale window
        assert cache.has_servable_entries()
        clock.now += 300
        assert not cache.has_servable_entries()


class TestSingleFlight:
    @pytest.mark.asyncio
    async def test_concurrent_misses_share_one_load(self, cache):
        calls = 0
        release = asyncio.Event()

        async def loader() -> AuthResult:
            nonlocal calls
            calls += 1
            await release.wait()
            cache.put("k", _result(), credential_ttl=3600)
            return _result()

        waiters = [
            asyncio.create_task(cache.get_or_load("k", loader)) for _ in range(50)
        ]
        await asyncio.sleep(0)
        release.set()
        results = await asyncio.gather(*waiters)
        assert calls == 1
        assert all(r == _result() for r in results)
        assert cache.coalesced_total == 49
        # Subsequent call is a pure L1 hit.
        assert await cache.get_or_load("k", loader) == _result()
        assert calls == 1

    @pytest.mark.asyncio
    async def test_errors_propagate_to_all_waiters_and_are_not_cached(self, cache):
        calls = 0
        release = asyncio.Event()

        async def loader() -> AuthResult:
            nonlocal calls
            calls += 1
            await release.wait()
            raise RuntimeError("boom")

        waiters = [
            asyncio.create_task(cache.get_or_load("k", loader)) for _ in range(3)
        ]
        await asyncio.sleep(0)
        release.set()
        results = await asyncio.gather(*waiters, return_exceptions=True)
        assert all(isinstance(r, RuntimeError) for r in results)
        assert calls == 1
        with pytest.raises(RuntimeError):
            await cache.get_or_load("k", loader)
        assert calls == 2

    @pytest.mark.asyncio
    async def test_cancelled_leader_does_not_cancel_other_waiters(self, cache):
        release = asyncio.Event()

        async def loader() -> AuthResult:
            await release.wait()
            return _result()

        leader = asyncio.create_task(cache.get_or_load("k", loader))
        await asyncio.sleep(0)
        follower = asyncio.create_task(cache.get_or_load("k", loader))
        await asyncio.sleep(0)
        leader.cancel()
        await asyncio.sleep(0)
        release.set()
        assert await follower == _result()
        assert leader.cancelled()
