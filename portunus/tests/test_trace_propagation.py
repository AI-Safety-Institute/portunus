"""X-Ray trace-id propagation under a real uvicorn server.

Regression test for the 2026-07-02 pipeline outage: uvicorn >=0.47.0 eagerly
imports the ASGI app in the parent process (encode/uvicorn#2919), before the
serving event loop exists. XRayService() runs at import time and AsyncContext()
binds its task factory to whatever loop exists at construction, so segments
created by LoggingMiddleware never reach request handlers —
``xray_recorder.current_segment()`` returns None and every request is logged
with request_id="No-Trace-Id". Downstream, that collapses all proxy logs into a
single request_id group and OOMs the joined-logs ETL.

TestClient cannot catch this (no real server loop / import ordering), so this
test boots an actual uvicorn subprocess with the same flags production uses and
asserts the trace id from an ALB-style X-Amzn-Trace-Id header round-trips into
the handler's current segment.
"""

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

APP_SOURCE = '''
from fastapi import FastAPI
from portunus.logging import LoggingMiddleware
from portunus.services.xray_service import XRayService

xray_service = XRayService()  # module scope, exactly like portunus.app

app = FastAPI(title="Portunus Authorisation Provider")
app.add_middleware(LoggingMiddleware)


@app.get("/trace")
async def trace():
    segment = xray_service.recorder.current_segment()
    return {"request_id": segment.trace_id if segment else "No-Trace-Id"}
'''


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def uvicorn_server(tmp_path: Path):
    """Boot the minimal repro app under a real uvicorn subprocess."""
    (tmp_path / "trace_app.py").write_text(APP_SOURCE)
    port = _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "trace_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--loop",
            "asyncio",  # matches the production CMD
            "--log-level",
            "warning",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "AWS_XRAY_DAEMON_ADDRESS": "127.0.0.1:2000",
            # conftest.py disables the SDK session-wide (dummy segments with
            # zeroed trace ids); this test exists to exercise the real SDK.
            "AWS_XRAY_SDK_ENABLED": "true",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                httpx.get(f"{base_url}/trace", timeout=1)
                break
            except httpx.TransportError:
                if proc.poll() is not None:
                    out = proc.stdout.read().decode() if proc.stdout else ""
                    pytest.fail(f"uvicorn exited early:\n{out}")
                time.sleep(0.2)
        else:
            pytest.fail("uvicorn did not become ready within 30s")
        yield base_url
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_trace_id_reaches_handler_segment(uvicorn_server: str) -> None:
    """An ALB-style trace header must round-trip into the handler's segment.

    This is what makes every proxied request's log request_id unique; if it
    regresses, all logs collapse into "No-Trace-Id" and the joined-logs ETL
    falls over.
    """
    for _ in range(3):
        trace_id = f"1-{secrets.token_hex(4)}-{secrets.token_hex(12)}"
        resp = httpx.get(
            f"{uvicorn_server}/trace",
            headers={"X-Amzn-Trace-Id": f"Root={trace_id}"},
            timeout=5,
        )
        assert resp.status_code == 200
        assert resp.json()["request_id"] == trace_id


def test_missing_trace_header_falls_back(uvicorn_server: str) -> None:
    """Without a trace header the request id degrades to a shared constant.

    Two constant fallbacks exist today: "No-Trace-Id" (handler sees no segment
    at all — the broken-propagation path) and the zeroed dummy trace id (the
    unsampled DummySegment created when the header is absent). Documented
    behaviour, not desirable: any constant fallback collapses log rows into one
    request_id group downstream. If this assertion breaks because the fallback
    became a unique per-request id, update it — that change is an improvement.
    """
    resp = httpx.get(f"{uvicorn_server}/trace", timeout=5)
    assert resp.status_code == 200
    assert resp.json()["request_id"] in (
        "No-Trace-Id",
        "1-00000000-000000000000000000000000",
    )
