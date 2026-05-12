"""WebSocket echo server with scriptable failure-mode endpoints.

The default path (``/``) is the legacy echo behaviour. Additional paths
let tests exercise WS failure scenarios without depending on a real
upstream provider:

* ``/echo`` — same as default, kept explicit for readability in tests.
* ``/close-after/N`` — echo each message; after the Nth message, send a
  WS close frame (code 1000, "ok") and close the TCP connection cleanly.
  Use to assert that Portunus propagates upstream-initiated closes.
* ``/echo-then-die`` — echo a single message, then drop the underlying
  TCP socket without sending a close frame. Use to assert that an
  abrupt upstream disconnect surfaces to the client as a clean error.
* ``/malformed`` — accept the WS handshake, then send raw bytes that
  don't form a valid WS frame. Use to assert that Portunus reports the
  upstream as broken rather than passing garbage through silently.

``/health`` (HTTP) returns 200 for ALB health checks.
"""

import asyncio
import http
import os
from urllib.parse import urlparse

import websockets
from websockets.server import WebSocketServerProtocol


CLOSE_AFTER_PREFIX = "/close-after/"


async def _handler(websocket: WebSocketServerProtocol) -> None:
    path = websocket.path

    if path == "/" or path == "/echo":
        await _echo_forever(websocket)
        return

    if path.startswith(CLOSE_AFTER_PREFIX):
        n_str = path[len(CLOSE_AFTER_PREFIX):]
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
    """Echo one message, then drop the TCP connection without a close frame.

    Mimics an upstream that crashes mid-stream. Tests should observe a
    clean WS-error on the client side, not a hang.
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

    The ``websockets`` library will treat our direct transport.write as
    leaving the framing layer entirely, so the bytes reach the peer
    without further encoding.
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
