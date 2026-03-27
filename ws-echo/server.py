"""Minimal WebSocket echo server for testing the Portunus WS relay."""

import asyncio
import http
import os

import websockets


async def echo(websocket: websockets.WebSocketServerProtocol) -> None:
    async for message in websocket:
        await websocket.send(message)


def health_check(path, headers):
    """Return 200 for /health so ALB health checks pass."""
    if path == "/health":
        return http.HTTPStatus.OK, [], b"ok\n"


async def main() -> None:
    port = int(os.environ.get("PORT", "80"))
    async with websockets.serve(echo, "0.0.0.0", port, process_request=health_check):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
