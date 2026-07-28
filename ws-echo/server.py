"""WebSocket echo server with scriptable handlers for end-to-end tests.

**Positive-path / SDK shape**
* ``/`` and ``/echo`` — bidirectional echo.
* ``/v1/responses`` — minimal OpenAI Responses-API mock. Emits
  ``response.created`` then ``RESPONSE_CHUNKS`` (default 3)
  ``response.output_text.delta`` events at ``CHUNK_INTERVAL_SEC`` (default
  0.1s), then ``response.completed``.

**Failure-mode**
* ``/close-after/N`` — echo N messages, then close cleanly with 1000.
* ``/echo-then-die`` — echo once, then abort the TCP socket (no close).
* ``/malformed`` — accept handshake, then write invalid frame bytes.

``/health`` (HTTP) returns 200 for ALB readiness checks.
"""

import asyncio
import http
import json
import os
import uuid

import websockets
from websockets.server import WebSocketServerProtocol

CLOSE_AFTER_PREFIX = "/close-after/"


async def _handler(websocket: WebSocketServerProtocol) -> None:
    path = websocket.path

    if path == "/" or path == "/echo":
        await _echo_forever(websocket)
        return

    if path.startswith(CLOSE_AFTER_PREFIX):
        n_str = path[len(CLOSE_AFTER_PREFIX) :]
        try:
            n = int(n_str)
        except ValueError:
            await websocket.close(code=1008, reason=f"invalid count: {n_str!r}")
            return
        await _close_after(websocket, n)
        return

    if path == "/echo-then-die":
        await _echo_then_die(websocket)
        return

    if path == "/malformed":
        await _malformed(websocket)
        return

    if path == "/v1/responses":
        await _openai_responses_mock(websocket)
        return

    await websocket.close(code=1008, reason=f"unknown path: {path!r}")


async def _echo_forever(websocket: WebSocketServerProtocol) -> None:
    async for message in websocket:
        await websocket.send(message)


async def _close_after(websocket: WebSocketServerProtocol, n: int) -> None:
    """Echo the first ``n`` messages, then close cleanly with code 1000."""
    count = 0
    async for message in websocket:
        await websocket.send(message)
        count += 1
        if count >= n:
            await websocket.close(code=1000, reason="close-after limit reached")
            return


async def _echo_then_die(websocket: WebSocketServerProtocol) -> None:
    """Echo one message, then abort the TCP socket without a close frame.

    Mimics an upstream that crashes mid-stream (client should see a WS error,
    not a hang).
    """
    async for message in websocket:
        await websocket.send(message)
        break
    # Reach into the transport and close abruptly so the peer sees a
    # connection reset rather than a graceful WS close.
    transport = websocket.transport
    if transport is not None:
        transport.abort()


async def _malformed(websocket: WebSocketServerProtocol) -> None:
    """Accept the handshake, then write bytes that don't form a valid WS frame.

    Direct ``transport.write`` bypasses the ``websockets`` framing layer, so
    the raw bytes reach the peer unencoded.
    """
    transport = websocket.transport
    if transport is None:
        return
    # 0xFF as a first byte sets every framing reserved bit, which is
    # invalid per RFC 6455. Followed by a short payload that doesn't
    # match a sane length prefix.
    transport.write(b"\xff\x00\x00garbage")
    await asyncio.sleep(0.05)  # let the bytes flush
    transport.close()


async def _openai_responses_mock(websocket: WebSocketServerProtocol) -> None:
    """Minimal OpenAI Responses-API mock over WebSocket.

    Waits for one client frame, then emits ``response.created`` →
    ``response.output_text.delta`` × N → ``response.completed`` as JSON text
    frames. Env config (ws-echo container):
      RESPONSE_CHUNKS       number of delta chunks (default 3)
      CHUNK_INTERVAL_SEC    delay between chunks (default 0.1)
    """
    chunks = int(os.environ.get("RESPONSE_CHUNKS", "3"))
    interval = float(os.environ.get("CHUNK_INTERVAL_SEC", "0.1"))

    # Wait for the client's request — Codex / openai-python sends the
    # initial request as the first frame after the handshake.
    try:
        await asyncio.wait_for(websocket.recv(), timeout=5)
    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
        return

    response_id = f"resp_{uuid.uuid4().hex[:24]}"

    await websocket.send(
        json.dumps(
            {
                "type": "response.created",
                "response": {"id": response_id, "status": "in_progress"},
            }
        )
    )

    for i in range(chunks):
        await asyncio.sleep(interval)
        await websocket.send(
            json.dumps(
                {
                    "type": "response.output_text.delta",
                    "response_id": response_id,
                    "delta": f"chunk-{i} ",
                }
            )
        )

    await websocket.send(
        json.dumps(
            {
                "type": "response.completed",
                "response": {"id": response_id, "status": "completed"},
            }
        )
    )


def _process_request(path: str, headers):
    """Return 200 for /health so ALB health checks pass without an upgrade."""
    if path == "/health":
        return http.HTTPStatus.OK, [], b"ok\n"
    return None


async def main() -> None:
    port = int(os.environ.get("PORT", "80"))
    async with websockets.serve(
        _handler, "0.0.0.0", port, process_request=_process_request
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
