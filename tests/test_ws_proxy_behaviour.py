"""WebSocket behaviour tests driven through Portunus.

Companion to ``test_http_proxy_behaviour.py``; per-test (not corpus-driven)
because WS behaviours have heterogeneous assertion shapes.

Each test exercises one ``ws-echo/server.py`` route:
  /close-after/N → server-initiated close with code 1000
  /echo-then-die → abrupt TCP reset after one echoed message
  /malformed     → invalid WS frame bytes after the handshake

Runs against the local docker-compose stack (Envoy + Portunus + ws-echo +
LocalStack); no real AWS or upstream access required.
"""

# ruff: noqa: E501, E402
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys

import pytest
import websockets.exceptions as wse

# ``websockets.asyncio.client`` is the modern API (``additional_headers``);
# the top-level ``websockets.connect`` is the legacy client (``extra_headers``).
from websockets.asyncio.client import connect as _ws_connect  # noqa: E402
from websockets.exceptions import ConnectionClosed

# Add portunus to the path so conftest helpers import cleanly.
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))
os.environ["AWS_XRAY_SDK_ENABLED"] = "false"
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")

from conftest import encode_base64  # noqa: E402

# Envoy's WS route has ``prefix: "/"`` and forwards the path as-is to
# the ws-echo upstream, whose handlers match exact paths (``/echo``,
# ``/close-after/N``, etc.). So the base URL has no extra prefix.
PROXY_WS_BASE = "ws://localhost:8888"


def _auth_header(api_key_prefix: str = "Bearer ") -> str:
    """Build the Bearer payload that the local stack's seeded secret accepts."""
    return f"{api_key_prefix}{encode_base64({'credentials': {}, 'secret_arn': ''})}"


def _close_code(exc: ConnectionClosed) -> int:
    """Pull the observed close code out of a ConnectionClosed exception.

    websockets v12 / v13 disagree on field names; this normalises both.
    """
    if hasattr(exc, "rcvd") and exc.rcvd is not None:
        return exc.rcvd.code
    return exc.code  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Bidirectional frame transport — base sanity that the failure-mode tests
# below are observing failures and not the absence of basic transport.
# ---------------------------------------------------------------------------


def _do_raw_upgrade(
    path: str, *, upgrade_token: str = "websocket"
) -> tuple[bytes, dict[str, str]]:
    """Send a raw WS upgrade to the proxy and parse the response.

    Bypasses the ``websockets`` client to observe the wire response Envoy
    emits regardless of client tolerance. Returns the HTTP status line and
    lowercase response headers — used to assert wire-protocol invariants on
    the 101 (e.g. no Transfer-Encoding, RFC 7230 §3.3.1). ``upgrade_token``
    varies the ``Upgrade`` value's case to exercise the case-insensitive match.
    """
    sock = socket.create_connection(("localhost", 8888), timeout=5)
    sock.settimeout(5)
    try:
        # Minimal RFC 6455 §1.3 upgrade request. ``Sec-WebSocket-Key`` is the
        # RFC 6455 §1.3 example nonce; we only assert on headers of the 101.
        auth = _auth_header()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: localhost:8888\r\n"
            f"Authorization: {auth}\r\n"
            f"Upgrade: {upgrade_token}\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode("ascii")
        sock.sendall(request)

        # Read until end-of-headers marker. WS 101s are small enough
        # that one buffered recv loop is fine.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        header_block, _, _ = buf.partition(b"\r\n\r\n")
    finally:
        sock.close()

    lines = header_block.split(b"\r\n")
    status_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.decode("ascii").strip().lower()] = value.decode("ascii").strip()
    return status_line, headers


# ---------------------------------------------------------------------------
# Bidirectional frame transport — base sanity that the failure-mode tests
# below are observing failures and not the absence of basic transport.
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize(
    "upgrade_token",
    ["websocket", "WebSocket", "WEBSOCKET"],
    ids=["lower", "mixed", "upper"],
)
def test_ws_route_matches_upgrade_header_case_insensitively(
    docker_setup, upgrade_token
):
    """RFC 6455 §4.2.1: ``Upgrade`` tokens are case-insensitive.

    Envoy's route header uses ``ignore_case: true`` so every case variant
    routes to the ws_upstream cluster (answers 101) rather than the plain HTTP
    cluster (would 400 / 426 / hang).
    """
    status, _ = _do_raw_upgrade("/echo", upgrade_token=upgrade_token)
    assert (
        b"101" in status
    ), f"expected 101 Switching Protocols for {upgrade_token!r}, got {status!r}"


@pytest.mark.slow
def test_ws_upgrade_101_response_has_no_transfer_encoding_chunked_header(
    docker_setup,
):
    """101 Switching Protocols must not carry Transfer-Encoding: chunked.

    RFC 7230 §3.3.1 forbids message-framing headers on any 1xx response.
    Envoy 1.36 in ext_proc ``FULL_DUPLEX_STREAMED`` body mode mis-frames the
    101 — it strips ``Content-Length: 0`` and appends ``Transfer-Encoding:
    chunked``, which ``websockets`` v13+ refuses to parse. Fixed by
    ``ExtProcPerRoute.overrides.processing_mode`` forcing STREAMED (not FDS)
    on the WS route. Asserted via raw socket so a library upgrade can't mask
    the regression.
    """
    status, headers = _do_raw_upgrade("/echo")
    assert (
        b"101" in status
    ), f"expected 101 Switching Protocols, got status line {status!r}"
    assert "transfer-encoding" not in headers, (
        "RFC 7230 §3.3.1 forbids Transfer-Encoding on 1xx responses; "
        f"got: {headers.get('transfer-encoding')!r}"
    )


@pytest.mark.asyncio
@pytest.mark.slow
async def test_text_message_round_trips_through_portunus_to_echo_upstream(
    docker_setup,
):
    headers = {"Authorization": _auth_header()}
    async with _ws_connect(f"{PROXY_WS_BASE}/echo", additional_headers=headers) as ws:
        await ws.send("hello")
        reply = await asyncio.wait_for(ws.recv(), timeout=5)
    assert reply == "hello"


@pytest.mark.asyncio
@pytest.mark.slow
async def test_binary_message_round_trips_through_portunus_to_echo_upstream(
    docker_setup,
):
    headers = {"Authorization": _auth_header()}
    payload = bytes(range(256))  # full byte-value sweep
    async with _ws_connect(f"{PROXY_WS_BASE}/echo", additional_headers=headers) as ws:
        await ws.send(payload)
        reply = await asyncio.wait_for(ws.recv(), timeout=5)
    assert reply == payload


# ---------------------------------------------------------------------------
# Server-initiated close — propagated to the client with the upstream's code
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.slow
async def test_upstream_close_after_n_messages_propagates_to_client_with_code_1000(
    docker_setup,
):
    """Upstream close-after-N propagates the close code through Portunus.

    ws-echo's /close-after/2 echoes two messages then closes with 1000; the
    client should observe the same code, not a hang or transport error.
    """
    headers = {"Authorization": _auth_header()}
    async with _ws_connect(
        f"{PROXY_WS_BASE}/close-after/2", additional_headers=headers
    ) as ws:
        await ws.send("one")
        assert await asyncio.wait_for(ws.recv(), timeout=5) == "one"
        await ws.send("two")
        assert await asyncio.wait_for(ws.recv(), timeout=5) == "two"

        with pytest.raises(ConnectionClosed) as exc_info:
            await asyncio.wait_for(ws.recv(), timeout=5)

    assert _close_code(exc_info.value) == 1000


# ---------------------------------------------------------------------------
# Abrupt upstream disconnect — surfaces to the client as an error within a
# reasonable bound, not as a silent hang
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.slow
async def test_abrupt_upstream_tcp_reset_surfaces_to_client_as_connection_error(
    docker_setup,
):
    """Abrupt upstream TCP reset surfaces to the client, not a hang.

    /echo-then-die echoes once then drops the socket with no close frame;
    Portunus must propagate the broken upstream rather than hold the client open.
    """
    headers = {"Authorization": _auth_header()}
    async with _ws_connect(
        f"{PROXY_WS_BASE}/echo-then-die", additional_headers=headers
    ) as ws:
        await ws.send("only one")
        assert await asyncio.wait_for(ws.recv(), timeout=5) == "only one"

        with pytest.raises(ConnectionClosed):
            await asyncio.wait_for(ws.recv(), timeout=5)


# ---------------------------------------------------------------------------
# Malformed upstream frame — Portunus should not pass garbage to the client
# but should terminate the WS session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.slow
async def test_upstream_malformed_frame_terminates_session_within_timeout(
    docker_setup,
):
    """Malformed upstream frame bytes terminate the session.

    /malformed writes invalid frame bytes after the handshake; the client must
    see the session terminate rather than the corrupt bytes relayed verbatim.
    """
    headers = {"Authorization": _auth_header()}
    async with _ws_connect(
        f"{PROXY_WS_BASE}/malformed", additional_headers=headers
    ) as ws:
        with pytest.raises((ConnectionClosed, asyncio.IncompleteReadError)):
            await asyncio.wait_for(ws.recv(), timeout=5)


# ---------------------------------------------------------------------------
# Auth path — a WS upgrade against a route that requires auth fails cleanly
# without auth, in line with the HTTP behaviour spec's "auth failure on the
# upgrade returns 401/403, never establishes the WS"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.slow
async def test_ws_upgrade_without_authorization_header_is_rejected_before_upgrade(
    docker_setup,
):
    """Missing Authorization fails at the HTTP upgrade layer.

    websockets v13 renamed ``InvalidStatusCode`` → ``InvalidStatus``; tolerate
    both so this test survives a library bump in either direction.
    """
    rejected = tuple(
        cls
        for cls in (getattr(wse, "InvalidStatus", None), wse.InvalidStatusCode)
        if cls is not None
    ) + (ConnectionClosed,)

    with pytest.raises(rejected):
        async with _ws_connect(f"{PROXY_WS_BASE}/echo"):
            pass


# ---------------------------------------------------------------------------
# Codex-shaped streaming flow — drives ws-echo's /v1/responses mock to validate
# the path Codex / openai-python takes through the proxy.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.slow
async def test_codex_responses_api_streaming_events_arrive_in_order(
    docker_setup,
) -> None:
    """Drive a Responses-API-shaped stream through Portunus and assert ordering.

    Smoke for the codex_cli / openai-python WS path: the mock emits
    ``response.created`` → N ``response.output_text.delta`` → ``response.completed``.
    A WS-pipeline regression (dropped or reordered frames) shows up here.
    """
    async with _ws_connect(
        f"{PROXY_WS_BASE}/v1/responses",
        additional_headers={"Authorization": _auth_header()},
        open_timeout=5,
    ) as ws:
        # The mock waits for one frame from the client before emitting its
        # event stream. Send the kind of payload Codex sends — a single
        # request envelope.
        await ws.send(
            json.dumps({"input": "Say ready.", "model": "gpt-4o-mini", "stream": True})
        )

        events = []
        for _ in range(20):  # bounded — mock sends at most ~5
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                break
            events.append(json.loads(msg))
            if events[-1].get("type") == "response.completed":
                break

    types = [e["type"] for e in events]
    assert types[0] == "response.created", f"first event was {types[0]!r}"
    assert types[-1] == "response.completed", f"last event was {types[-1]!r}"
    delta_count = sum(1 for t in types if t == "response.output_text.delta")
    assert delta_count >= 1, f"no delta events arrived; got {types}"
