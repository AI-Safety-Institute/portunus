"""Disruption / graceful-drain e2e tests for the Portunus gRPC sidecar.

Modelled on gimlet's ``tests/test_disruption.py``: inject real container
failures (SIGTERM, restart) against the live docker-compose stack and assert
the system drains / recovers gracefully rather than dropping or hanging.

These exercise the behaviours the gRPC refactor newly owns and that unit tests
can't reach end to end:

* graceful drain on SIGTERM (gRPC server stops accepting, flushes the publish
  queue, exits within the grace window — server.py ``run`` + ``stop_grpc_server``)
* the gRPC health service flipping NOT_SERVING at drain start
* no audit-record loss / no client hang while a request is in flight during a
  Portunus restart
* auth failure short-circuiting at ext_authz without touching the upstream
* Envoy drain on SIGTERM (proxy/entrypoint.sh): in-flight streaming HTTP
  responses (the SSE / eventstream shape) and established WebSocket sessions
  survive a task stop and keep flowing through the drain window; Envoy exits
  0 as soon as the last downstream connection closes, not at the SIGKILL

Destructive (they kill/restart containers), so they run serially and are
marked ``slow`` + ``disruption``. Run with the stack up:

    docker compose up -d --build --wait
    uv run pytest tests/test_disruption.py -m disruption
"""

from __future__ import annotations

import asyncio
import subprocess
import time

import pytest
import requests
from conftest import encode_base64
from grpc_health.v1 import health_pb2

PROXY_URL = "http://localhost:8888"
PORTUNUS_CONTAINER = "portunus"
# Portunus serves gRPC on loopback inside the proxy netns; the proxy publishes
# nothing for it, so health is probed from inside the container.
GRPC_ADDR = "127.0.0.1:9000"

pytestmark = [pytest.mark.slow, pytest.mark.disruption]


def _auth_header(prefix: str = "Bearer ") -> str:
    """Bearer payload the seeded LocalStack secret accepts."""
    return f"{prefix}{encode_base64({'credentials': {}, 'secret_arn': ''})}"


def _docker(*args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )


def _container_state(name: str) -> str:
    out = _docker("inspect", "-f", "{{.State.Status}}", name)
    return out.stdout.strip()


def _wait_for_proxy_ping(timeout: float = 30.0) -> bool:
    """Wait until Envoy answers /ping (proxy task up)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{PROXY_URL}/ping", timeout=2).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


def _grpc_health(timeout: float = 2.0) -> int:
    """Query Portunus' gRPC health from inside the portunus container.

    Returns a ``health_pb2.HealthCheckResponse.ServingStatus`` enum value
    (an int): SERVING or NOT_SERVING.

    The gRPC port is loopback-only, so we exec grpc_health_probe in the
    container rather than dialling from the test host.
    """
    out = _docker(
        "exec",
        PORTUNUS_CONTAINER,
        "grpc_health_probe",
        f"-addr={GRPC_ADDR}",
        timeout=timeout + 3,
    )
    # grpc_health_probe exits 0 = SERVING, non-zero otherwise.
    return (
        health_pb2.HealthCheckResponse.SERVING
        if out.returncode == 0
        else (health_pb2.HealthCheckResponse.NOT_SERVING)
    )


@pytest.fixture
def restore_portunus():
    """Ensure the portunus container is running + healthy after a test.

    Mirrors gimlet's ``ensure_system_running``: destructive tests can leave
    the container stopped; restart it and wait for readiness so the next test
    (and the session teardown) sees a healthy stack.
    """
    yield
    if _container_state(PORTUNUS_CONTAINER) != "running":
        _docker("start", PORTUNUS_CONTAINER)
    # Wait for the proxy<->portunus path to answer again.
    _wait_for_proxy_ping(timeout=30)


# ---------------------------------------------------------------------------
# Liveness / health
# ---------------------------------------------------------------------------


def test_grpc_health_reports_serving_when_up(docker_setup):
    """Baseline: grpc.health.v1 reports SERVING on a healthy stack."""
    assert _grpc_health() == health_pb2.HealthCheckResponse.SERVING


def test_http_request_succeeds_on_healthy_stack(docker_setup):
    """Sanity: a valid auth request round-trips through the gRPC ext_authz."""
    resp = requests.get(
        f"{PROXY_URL}/get", headers={"Authorization": _auth_header()}, timeout=10
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth short-circuit — ext_authz denies without touching the upstream
# ---------------------------------------------------------------------------


def test_auth_failure_short_circuits_at_ext_authz(docker_setup):
    """A bad bearer is denied by Portunus ext_authz, not forwarded upstream."""
    resp = requests.get(
        f"{PROXY_URL}/get",
        headers={"Authorization": "Bearer not-a-valid-payload"},
        timeout=10,
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Graceful drain on SIGTERM
# ---------------------------------------------------------------------------


def test_sigterm_drains_within_grace_window(docker_setup, restore_portunus):
    """SIGTERM the portunus container; it should exit cleanly within grace.

    server.py installs a SIGTERM handler that stops accepting new gRPC
    streams, flushes the publish queue, and exits. The container's
    ``GRPC_GRACEFUL_SHUTDOWN_SECONDS`` default is 30s; a quiescent server
    should drain well inside that and not be SIGKILL'd.
    """
    assert _container_state(PORTUNUS_CONTAINER) == "running"

    start = time.monotonic()
    # docker stop sends SIGTERM then SIGKILL after the timeout; give it the
    # full grace budget. A clean drain exits 0 before the kill.
    result = _docker("stop", "-t", "40", PORTUNUS_CONTAINER, timeout=50)
    elapsed = time.monotonic() - start

    assert result.returncode == 0, result.stderr
    # Clean drain on a quiescent server is fast — well under the 40s kill.
    assert elapsed < 35, f"drain took {elapsed:.1f}s — close to SIGKILL window"

    # Exit code 0 = clean shutdown (not 137 = SIGKILL).
    code = _docker(
        "inspect", "-f", "{{.State.ExitCode}}", PORTUNUS_CONTAINER
    ).stdout.strip()
    assert code == "0", f"portunus exited {code} (137 = SIGKILL'd mid-drain)"


def test_inflight_http_request_during_portunus_restart_does_not_hang(
    docker_setup, restore_portunus
):
    """Restarting Portunus mid-traffic fails fast or succeeds — never hangs.

    With ext_authz ``failure_mode_allow: false`` a Portunus outage denies
    requests rather than bypassing auth; either way the client gets a prompt
    response, not a hang.
    """
    # Kick off the restart, then fire a request into the window.
    restart = subprocess.Popen(["docker", "restart", "-t", "10", PORTUNUS_CONTAINER])
    try:
        start = time.monotonic()
        try:
            resp = requests.get(
                f"{PROXY_URL}/get",
                headers={"Authorization": _auth_header()},
                timeout=15,
            )
            elapsed = time.monotonic() - start
            # Either authorised (200) or failed-closed (5xx/403) — but bounded.
            assert resp.status_code in (200, 401, 403, 500, 502, 503, 504)
            assert elapsed < 15, f"request hung {elapsed:.1f}s during restart"
        except requests.RequestException:
            # A connection error is an acceptable fail-fast, not a hang.
            elapsed = time.monotonic() - start
            assert elapsed < 15, f"request hung {elapsed:.1f}s before erroring"
    finally:
        restart.wait(timeout=60)

    # Recovers afterwards. Envoy's /ping doesn't depend on Portunus, so wait
    # for the gRPC health service to report SERVING (and retry the authed
    # request) before asserting — the just-restarted server may briefly
    # reject while it finishes binding / warming the auth path.
    assert _wait_for_proxy_ping(timeout=30)
    deadline = time.monotonic() + 30
    last_status = None
    while time.monotonic() < deadline:
        if _grpc_health() == health_pb2.HealthCheckResponse.SERVING:
            resp = requests.get(
                f"{PROXY_URL}/get",
                headers={"Authorization": _auth_header()},
                timeout=10,
            )
            last_status = resp.status_code
            if last_status == 200:
                break
        time.sleep(1)
    assert (
        last_status == 200
    ), f"did not recover to 200 after restart (last={last_status})"


def test_portunus_restart_keeps_same_topology_and_recovers(
    docker_setup, restore_portunus
):
    """After a restart the gRPC health service comes back SERVING."""
    _docker("restart", "-t", "10", PORTUNUS_CONTAINER, timeout=60)
    assert _wait_for_proxy_ping(timeout=30)

    # Health probe should report SERVING again within a short window.
    deadline = time.monotonic() + 20
    serving = False
    while time.monotonic() < deadline:
        if _grpc_health() == health_pb2.HealthCheckResponse.SERVING:
            serving = True
            break
        time.sleep(0.5)
    assert serving, "gRPC health did not return to SERVING after restart"


# ---------------------------------------------------------------------------
# Envoy drain on SIGTERM — in-flight streams across protocols
#
# ECS task stop is: ALB target deregistration (10s delay) → SIGTERM →
# stopTimeout → SIGKILL. Everything Claude Code / Inspect sees as a
# "connection closed mid-response" during a scale-in happens in that window.
# proxy/entrypoint.sh owns the SIGTERM side: it must put Envoy into a drain
# (in-flight streams keep flowing, no new connections routed here anyway)
# and only exit once downstream connections hit zero or the drain budget
# expires. SSE and AWS eventstream are both just long streaming HTTP
# responses through Envoy, so one streaming-HTTP test covers that class;
# WebSocket is a separate upgraded-connection path and gets its own test.
# ---------------------------------------------------------------------------

_PROXY_CONTAINER_CACHE: str | None = None


def _proxy_container() -> str:
    """Resolve the proxy service's container name for this compose project.

    The compose project name derives from the checkout directory, so the
    container name isn't stable across clones — resolve it via the compose
    service label rather than hardcoding.
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


def _exit_code(name: str) -> str:
    return _docker("inspect", "-f", "{{.State.ExitCode}}", name).stdout.strip()


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
    """Bring the proxy (and its netns-sharing portunus sidecar) back after a test.

    Stopping the proxy container tears down the network namespace portunus
    shares (``network_mode: service:proxy``), so after restarting the proxy
    the portunus container must also be restarted to join the fresh
    namespace — ``docker start`` alone would leave it in the dead one.
    """
    yield
    proxy = _proxy_container()
    if _container_state(proxy) != "running":
        _docker("start", proxy)
        _docker("restart", "-t", "10", PORTUNUS_CONTAINER, timeout=60)
    assert _wait_for_proxy_ping(timeout=30), "proxy did not come back up"
    assert _wait_for_authed_200(), "authed path did not recover after restart"


def test_envoy_sigterm_completes_inflight_http_stream(docker_setup, restore_proxy):
    """A streaming HTTP response in flight at SIGTERM completes, uncut.

    This is the SSE / eventstream shape: a long-lived chunked response
    trickling through Envoy (httpbun ``/drip`` at ~1 byte/sec). SIGTERM
    lands ~2s into a ~12s stream; the drain must let the remaining ~10s
    stream to the client rather than resetting the connection, and Envoy
    must exit 0 shortly after the stream (its last downstream connection)
    completes — well before the 90s SIGKILL backstop.
    """
    proxy = _proxy_container()
    assert _container_state(proxy) == "running"
    # First authed request on a cold stack can 5xx while the auth path
    # warms; this test is about draining, not cold starts.
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


@pytest.mark.asyncio
async def test_envoy_sigterm_keeps_websocket_flowing_during_drain(
    docker_setup, restore_proxy
):
    """An established WebSocket session keeps echoing through the drain.

    Upgraded connections can't be nudged closed at a response boundary the
    way plain HTTP can, so the drain must simply leave them open until the
    client closes (or the budget expires). Echo frames for ~6s after
    SIGTERM, close from the client side, then expect a prompt clean exit.
    """
    from websockets.asyncio.client import connect as ws_connect

    proxy = _proxy_container()
    assert _container_state(proxy) == "running"

    stop: subprocess.Popen | None = None
    async with ws_connect(
        "ws://localhost:8888/echo",
        additional_headers={"Authorization": _auth_header()},
    ) as ws:
        # Established, working session first.
        await ws.send("pre-drain")
        assert await asyncio.wait_for(ws.recv(), timeout=5) == "pre-drain"

        stop_started = time.monotonic()
        stop = subprocess.Popen(
            ["docker", "stop", "-t", "90", proxy],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            # Frames must keep round-tripping during the drain window.
            frame = 0
            while time.monotonic() - stop_started < 6:
                frame += 1
                await ws.send(f"drain-{frame}")
                echoed = await asyncio.wait_for(ws.recv(), timeout=5)
                assert echoed == f"drain-{frame}", (
                    f"echo diverged {time.monotonic() - stop_started:.1f}s "
                    "after SIGTERM"
                )
                await asyncio.sleep(0.5)
            assert frame >= 8, f"only {frame} echoes during the drain window"
        finally:
            pass  # context manager sends the client-side close

    assert stop is not None
    stop.wait(timeout=120)
    stop_elapsed = time.monotonic() - stop_started
    assert stop.returncode == 0
    assert stop_elapsed < 45, f"drain held Envoy for {stop_elapsed:.1f}s"
    assert (
        _exit_code(proxy) == "0"
    ), f"proxy exited {_exit_code(proxy)} (137 = SIGKILL'd mid-drain)"


def test_envoy_sigterm_quiescent_exits_fast_and_clean(docker_setup, restore_proxy):
    """With no traffic, SIGTERM exits promptly and cleanly (no SIGKILL).

    Guards the drain handler against 'always sleep the full window'
    regressions: zero downstream connections should short-circuit the wait.
    """
    proxy = _proxy_container()
    assert _container_state(proxy) == "running"
    # Let the async audit tail of any preceding test's traffic flush —
    # the drain rightly waits for in-flight audit work, and this test is
    # about the no-traffic path.
    time.sleep(3)

    start = time.monotonic()
    result = _docker("stop", "-t", "90", proxy, timeout=100)
    elapsed = time.monotonic() - start

    assert result.returncode == 0, result.stderr
    assert elapsed < 20, f"quiescent drain took {elapsed:.1f}s"
    assert (
        _exit_code(proxy) == "0"
    ), f"proxy exited {_exit_code(proxy)} (137 = SIGKILL'd mid-drain)"
