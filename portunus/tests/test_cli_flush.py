"""Tests for the CLI's flush-auth-cache command."""

import sys

import fakeredis
import fakeredis.aioredis
import pytest

from portunus import cli
from portunus.config import config
from portunus.services.state_service import StateService

PASSWORD = "synthetic-redis-password-do-not-print"


@pytest.fixture
def redis_target(monkeypatch):
    monkeypatch.setattr(config.redis, "host", "cache.example.internal")
    monkeypatch.setattr(config.redis, "port", 6380)
    monkeypatch.setattr(config.redis, "password", PASSWORD)


@pytest.fixture
def fake_server(monkeypatch):
    """A shared fake Redis the CLI's StateService connects to."""
    server = fakeredis.FakeServer()

    async def get_redis_client(self):
        return fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    monkeypatch.setattr(StateService, "get_redis_client", get_redis_client)
    seed = fakeredis.FakeRedis(server=server)
    seed.set("auth:one", "x")
    seed.set("auth:two", "y")
    return seed


def _run(monkeypatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["portunus", "flush-auth-cache", *args])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    code = exc.value.code
    assert isinstance(code, int)
    return code


def test_yes_flushes_and_reports_the_target(
    monkeypatch, capsys, redis_target, fake_server
):
    assert _run(monkeypatch, "--yes") == 0
    assert fake_server.dbsize() == 0
    out = capsys.readouterr()
    assert "cache.example.internal:6380" in out.out
    assert "database 0" in out.out
    assert PASSWORD not in out.out + out.err


def test_declined_prompt_flushes_nothing(
    monkeypatch, capsys, redis_target, fake_server
):
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert _run(monkeypatch) == 1
    assert fake_server.dbsize() == 2
    out = capsys.readouterr()
    assert "cache.example.internal:6380" in out.out
    assert PASSWORD not in out.out + out.err


def test_confirmed_prompt_flushes(monkeypatch, redis_target, fake_server):
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert _run(monkeypatch) == 0
    assert fake_server.dbsize() == 0


def test_redis_down_exits_non_zero(monkeypatch, capsys, unused_tcp_port):
    monkeypatch.setattr(config.redis, "host", "127.0.0.1")
    monkeypatch.setattr(config.redis, "port", unused_tcp_port)
    monkeypatch.setattr(config.redis, "password", PASSWORD)
    monkeypatch.setattr(config.redis, "use_tls", False)
    assert _run(monkeypatch, "--yes") == 1
    out = capsys.readouterr()
    assert f"127.0.0.1:{unused_tcp_port}" in out.out
    assert PASSWORD not in out.out + out.err
