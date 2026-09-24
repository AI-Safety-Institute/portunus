"""The shared Redis pool blocks at its cap instead of failing the command."""

import time

import pytest
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError

from portunus.config import config
from portunus.services.state_service import _build_redis_pool


def test_pool_is_blocking_and_configured(monkeypatch):
    monkeypatch.setattr(config.redis, "max_connections", 7)
    monkeypatch.setattr(config.redis, "pool_timeout_seconds", 0.25)
    monkeypatch.setattr(config.redis, "health_check_interval_seconds", 30)
    monkeypatch.setattr(config.redis, "use_tls", True)

    pool = _build_redis_pool()

    assert isinstance(pool, aioredis.BlockingConnectionPool)
    assert pool.max_connections == 7
    assert pool.timeout == 0.25
    assert pool.connection_class is aioredis.SSLConnection
    assert pool.connection_kwargs["ssl_cert_reqs"] == "required"
    assert pool.connection_kwargs["health_check_interval"] == 30


def test_pool_without_tls_uses_plain_connections(monkeypatch):
    monkeypatch.setattr(config.redis, "use_tls", False)

    pool = _build_redis_pool()

    assert pool.connection_class is aioredis.Connection
    assert "ssl_cert_reqs" not in pool.connection_kwargs


@pytest.mark.asyncio
async def test_exhausted_pool_waits_then_fails(monkeypatch):
    """At the cap the pool waits out its timeout rather than erroring at once.

    The default pool raises "Too many connections" immediately, which the
    auth path treats as a Redis failure and falls through to STS.
    """
    monkeypatch.setattr(config.redis, "max_connections", 1)
    monkeypatch.setattr(config.redis, "pool_timeout_seconds", 0.2)
    monkeypatch.setattr(config.redis, "use_tls", False)
    pool = _build_redis_pool()
    pool._in_use_connections.add(pool.make_connection())

    started = time.monotonic()
    with pytest.raises(ConnectionError, match="No connection available"):
        await pool.get_connection()
    assert time.monotonic() - started >= 0.15
