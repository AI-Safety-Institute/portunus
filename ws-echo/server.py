"""Test WebSocket server for the Portunus WS relay.

Two endpoints in one process so a single container can satisfy both
the legacy load-test scripts (which expect a literal echo) and the
WS-shutdown staging runbook (which needs an OpenAI Responses-API
compatible upstream so codex-style multi-turn sessions can flow
through the relay without burning real OpenAI quota):

- ``/v1/responses``  — speaks just enough of the OpenAI Responses
                       API WebSocket protocol to drive a multi-turn
                       client. Each ``response.create`` is answered
                       with a configurable-length stream of
                       ``output_text.delta`` events followed by
                       ``response.completed``.
- anything else      — literal echo. Existing k6 scripts hitting
                       ``/echo`` keep working unchanged.

Health probe at HTTP ``GET /health`` (handled by ``process_request``
before the upgrade), so container HEALTHCHECK and ALB target-group
probes work without engaging either WS handler.
"""

from __future__ import annotations

import asyncio
import http
import json
import logging
import os
import uuid

import websockets
from websockets.legacy.server import WebSocketServerProtocol

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [ws-echo] %(message)s",
)
logger = logging.getLogger(__name__)

CHUNKS = int(os.environ.get("RESPONSE_CHUNKS", "4"))
CHUNK_INTERVAL_SEC = float(os.environ.get("CHUNK_INTERVAL_SEC", "1.0"))


def _process_request(path: str, request_headers):
    """Short-circuit ``GET /health`` before the WS upgrade."""
    if path == "/health":
        return http.HTTPStatus.OK, [("Content-Type", "text/plain")], b"ok\n"
    return None


async def _echo(websocket: WebSocketServerProtocol) -> None:
    """Mirror every received message back to the sender."""
    async for message in websocket:
        await websocket.send(message)


async def _stream_response(
    websocket: WebSocketServerProtocol, request: dict
) -> None:
    """Stream a fake Responses API response to one ``response.create`` request.

    Emits the full event sequence so a real codex client can parse
    it: ``response.created`` → ``in_progress`` → ``output_item.added``
    → ``content_part.added`` → N ``output_text.delta`` →
    ``output_text.done`` → ``content_part.done`` →
    ``output_item.done`` → ``response.completed``.
    """
    response_id = f"resp_mock_{uuid.uuid4().hex[:12]}"
    item_id = f"msg_mock_{uuid.uuid4().hex[:12]}"
    previous_response_id = request.get("response", {}).get("previous_response_id")
    request_model = request.get("response", {}).get("model", "gpt-4o-mini")

    base_response = {
        "id": response_id,
        "object": "response",
        "status": "in_progress",
        "model": request_model,
        "previous_response_id": previous_response_id,
        "output": [],
    }
    await websocket.send(
        json.dumps({"type": "response.created", "response": base_response})
    )
    await websocket.send(
        json.dumps({"type": "response.in_progress", "response": base_response})
    )

    item_template = {
        "id": item_id,
        "object": "response.output_item",
        "type": "message",
        "status": "in_progress",
        "role": "assistant",
        "content": [],
    }
    await websocket.send(
        json.dumps(
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": item_template,
            }
        )
    )
    await websocket.send(
        json.dumps(
            {
                "type": "response.content_part.added",
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            }
        )
    )

    accumulated = ""
    for i in range(CHUNKS):
        await asyncio.sleep(CHUNK_INTERVAL_SEC)
        delta = f"chunk-{i + 1}/{CHUNKS} "
        accumulated += delta
        await websocket.send(
            json.dumps(
                {
                    "type": "response.output_text.delta",
                    "item_id": item_id,
                    "output_index": 0,
                    "content_index": 0,
                    "delta": delta,
                }
            )
        )

    final_text = accumulated.strip()
    final_part = {
        "type": "output_text",
        "text": final_text,
        "annotations": [],
    }
    await websocket.send(
        json.dumps(
            {
                "type": "response.output_text.done",
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "text": final_text,
            }
        )
    )
    await websocket.send(
        json.dumps(
            {
                "type": "response.content_part.done",
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": final_part,
            }
        )
    )
    completed_item = {
        **item_template,
        "status": "completed",
        "content": [final_part],
    }
    await websocket.send(
        json.dumps(
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": completed_item,
            }
        )
    )
    completed_response = {
        **base_response,
        "status": "completed",
        "output": [completed_item],
        "output_text": final_text,
        "usage": {
            "input_tokens": 10,
            "output_tokens": CHUNKS,
            "total_tokens": 10 + CHUNKS,
        },
    }
    await websocket.send(
        json.dumps({"type": "response.completed", "response": completed_response})
    )
    logger.info(
        f"completed response {response_id} "
        f"(prev={previous_response_id}, chunks={CHUNKS})"
    )


async def _responses(websocket: WebSocketServerProtocol) -> None:
    """Persistent WS handler that replays Responses API turns."""
    peer = websocket.remote_address
    logger.info(f"responses-api session opened from {peer}")
    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"non-JSON message from {peer}: {raw!r}")
                continue
            if msg.get("type") == "response.create":
                await _stream_response(websocket, msg)
            else:
                logger.info(f"ignoring unsupported message type: {msg.get('type')}")
    except websockets.exceptions.ConnectionClosed as exc:
        logger.info(f"responses-api session closed from {peer}: {exc.code} {exc.reason!r}")


async def _dispatch(websocket: WebSocketServerProtocol) -> None:
    """Pick the per-connection handler based on the upgrade path.

    websockets.legacy.server passes the requested path on
    ``websocket.path``. ``/v1/responses`` (and anything beneath it)
    gets the Responses API mock; everything else gets echo.
    """
    if websocket.path.startswith("/v1/responses"):
        await _responses(websocket)
    else:
        await _echo(websocket)


async def main() -> None:
    port = int(os.environ.get("PORT", "80"))
    logger.info(
        f"starting test WS server on :{port} "
        f"(responses chunks={CHUNKS}, interval={CHUNK_INTERVAL_SEC}s)"
    )
    async with websockets.serve(
        _dispatch, "0.0.0.0", port, process_request=_process_request
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
