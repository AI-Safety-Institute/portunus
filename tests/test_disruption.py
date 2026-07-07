"""Disruption e2e tests for Envoy's SIGTERM drain (proxy/entrypoint.sh).

ECS task stop is: ALB target deregistration (10s delay) → SIGTERM →
stopTimeout → SIGKILL. Every "connection closed mid-response" a client sees
during a scale-in or deploy happens in that window, because a bare SIGTERM
makes Envoy exit immediately and RST every open stream. The entrypoint's
drain orchestration must instead let in-flight plain-HTTP responses (the
SSE / AWS-eventstream shape — long streaming responses through Envoy)
complete, and exit as soon as the last one does.

Scope is plain HTTP only: WebSocket sessions are deliberately excluded
from the drain's connection count (they'd otherwise pin a stopping task
for the full budget) and are closed at drain end exactly as a bare SIGTERM
closes them today. WS-aware draining lands with the gRPC cutover (#19),
whose entrypoint and disruption suite supersede this file.

Destructive (they stop the proxy container), so marked ``slow`` +
``disruption``. Run with the stack up:

    docker compose up -d --build --wait
    uv run pytest tests/test_disruption.py -m disruption
"""

from __future__ import annotations

import subprocess
import time

import pytest
import requests
from conftest import encode_base64

PROXY_URL = "http://localhost:8888"

pytestmark = [pytest.mark.slow, pytest.mark.disruption]

_PROXY_CONTAINER_CACHE: str | None = None


def _auth_header(prefix: str = "Bearer ") -> str:
    """Bearer payload the seeded LocalStack secret accepts."""
    return f"{prefix}{encode_base64({'credentials': {}, 'secret_arn': ''})}"


def _docker(*args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )


def _proxy_container() -> str:
    """Resolve the proxy service's container name for this compose project.

    The compose project name derives from the checkout directory, so the
    container name isn't stable across clones — resolve it via the compose
    service rather than hardcoding.
    """
    global _PROXY_CONTAINER_CACHE
    if _PROXY_CONTAINER_CACHE is None:
        out = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}", "proxy"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        names = [line for line in out.stdout.splitlines() if line.strip()]
        assert names, f"could not resolve proxy container: {out.stderr}"
        _PROXY_CONTAINER_CACHE = names[0]
    return _PROXY_CONTAINER_CACHE


def _container_state(name: str) -> str:
    out = _docker("inspect", "-f", "{{.State.Status}}", name)
    return out.stdout.strip()


def _exit_code(name: str) -> str:
    return _docker("inspect", "-f", "{{.State.ExitCode}}", name).stdout.strip()


def _wait_for_proxy_ping(timeout: float = 30.0) -> bool:
    """Wait until the proxy answers /ping (Lua direct response, no auth)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{PROXY_URL}/ping", timeout=2).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


def _wait_for_authed_200(timeout: float = 45.0) -> bool:
    """Wait until an authorised request round-trips 200 through the stack."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.get(
                f"{PROXY_URL}/get",
                headers={"Authorization": _auth_header()},
                timeout=5,
            )
            if resp.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False


@pytest.fixture
def restore_proxy():
    """Bring the proxy container back after a destructive test.

    Portunus runs in its own container/netns on this branch, so restarting
    the proxy alone is sufficient (unlike the #19 sidecar layout).
    """
    yield
    proxy = _proxy_container()
    if _container_state(proxy) != "running":
        _docker("start", proxy)
    assert _wait_for_proxy_ping(timeout=30), "proxy did not come back up"
    assert _wait_for_authed_200(), "authed path did not recover after restart"


def test_envoy_sigterm_completes_inflight_http_stream(docker_setup, restore_proxy):
    """A streaming HTTP response in flight at SIGTERM completes, uncut.

    This is the SSE / eventstream shape: a long-lived chunked response
    trickling through Envoy (httpbun ``/drip`` at ~1 byte/sec). SIGTERM
    lands ~2s into a ~12s stream; the drain must let the remaining ~10s
    stream to the client rather than resetting the connection, and Envoy
    must exit 0 shortly after the stream (its last plain-HTTP downstream
    connection) completes — well before the 90s SIGKILL backstop.
    """
    proxy = _proxy_container()
    assert _container_state(proxy) == "running"
    # First authed request on a cold stack can 5xx while Portunus warms
    # its auth path; this test is about draining, not cold starts.
    assert _wait_for_authed_200(), "stack not serving authed traffic"

    num_bytes = 12
    received: list[float] = []
    stop: subprocess.Popen | None = None
    stop_started = 0.0

    # ``Connection: close`` so Envoy closes the wire once the response
    # completes — otherwise the client's parked keep-alive connection
    # (which the drain rightly cannot force-close mid-nothing on HTTP/1.1)
    # holds the drain open until its deadline. Prod behaves the same way:
    # the ALB closes its idle keep-alives to a deregistered target.
    # The finally ensures the background ``docker stop`` has landed before
    # restore_proxy runs, even when the stream dies mid-read (the failure
    # mode this test exists to catch) — otherwise the fixture's
    # ``docker start`` races the still-running stop.
    try:
        with requests.get(
            f"{PROXY_URL}/drip?duration={num_bytes}&numbytes={num_bytes}&delay=0",
            headers={"Authorization": _auth_header(), "Connection": "close"},
            stream=True,
            timeout=(5, 30),
        ) as resp:
            assert resp.status_code == 200
            for _ in resp.iter_content(chunk_size=1):
                received.append(time.monotonic())
                if stop is None:
                    # First byte is flowing — SIGTERM the proxy under it.
                    stop_started = time.monotonic()
                    stop = subprocess.Popen(
                        ["docker", "stop", "-t", "90", proxy],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
    finally:
        if stop is not None:
            stop.wait(timeout=120)
    stop_elapsed = time.monotonic() - stop_started

    assert stop is not None, "stream produced no bytes"

    assert len(received) == num_bytes, (
        f"stream cut mid-response: {len(received)}/{num_bytes} bytes "
        f"({(received[-1] - stop_started):.1f}s after SIGTERM was issued)"
    )
    # The stream must have kept flowing well into the drain, not raced it.
    assert (
        received[-1] - stop_started > 3
    ), "stream finished before the drain was meaningfully exercised"
    assert stop.returncode == 0
    # Drain exits when connections hit zero — not at the 90s SIGKILL.
    assert stop_elapsed < 45, f"drain held Envoy for {stop_elapsed:.1f}s"
    assert (
        _exit_code(proxy) == "0"
    ), f"proxy exited {_exit_code(proxy)} (137 = SIGKILL'd mid-drain)"


def test_envoy_sigterm_quiescent_exits_fast_and_clean(docker_setup, restore_proxy):
    """With no traffic, SIGTERM exits promptly and cleanly (no SIGKILL).

    Guards the drain handler against 'always sleep the full window'
    regressions: zero plain-HTTP downstream connections should
    short-circuit the wait.
    """
    proxy = _proxy_container()
    assert _container_state(proxy) == "running"
    # Let the async audit tail of any preceding test's traffic flush —
    # the drain rightly waits for in-flight Lua→Portunus log calls, and
    # this test is about the no-traffic path.
    time.sleep(3)

    start = time.monotonic()
    result = _docker("stop", "-t", "90", proxy, timeout=100)
    elapsed = time.monotonic() - start

    assert result.returncode == 0, result.stderr
    assert elapsed < 20, f"quiescent drain took {elapsed:.1f}s"
    assert (
        _exit_code(proxy) == "0"
    ), f"proxy exited {_exit_code(proxy)} (137 = SIGKILL'd mid-drain)"
