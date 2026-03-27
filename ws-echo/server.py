"""Minimal WebSocket echo server for testing the Portunus WS relay."""

import asyncio
import os

import websockets


async def echo(websocket: websockets.WebSocketServerProtocol) -> None:
    async for message in websocket:
        await websocket.send(message)


async def main() -> None:
    port = int(os.environ.get("PORT", "80"))
    async with websockets.serve(echo, "0.0.0.0", port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
