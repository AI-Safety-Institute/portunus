# ruff: noqa: E501, E402
"""Audit-pipeline smoke tests for the gRPC ext_authz/ext_proc model.

Drives a realistic client flow (a Codex-shaped Responses-API WS stream)
through Portunus and asserts the expected audit
records land in LocalStack S3 — the pipeline downstream analytics consumes. Transport-level
behaviour lives in ``test_ws_proxy_behaviour.py`` / ``test_http_proxy_behaviour.py``.

Run with the docker-compose stack up. Marked ``slow`` so CI lint/type-check skip them.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")

from conftest import _read_audit_s3_records, encode_base64  # noqa: E402

# Import the ws-client used by the behaviour suite so we're on the
# same client surface (additional_headers, asyncio API).
from websockets.asyncio.client import connect as _ws_connect  # noqa: E402

PROXY_WS_BASE = "ws://localhost:8888"


def _auth_header(api_key_prefix: str = "Bearer ") -> str:
    return f"{api_key_prefix}{encode_base64({'credentials': {}, 'secret_arn': ''})}"


async def _wait_for_s3_records(
    stream: str,
    predicate,
    *,
    timeout: float = 20.0,
    poll_interval: float = 0.5,
) -> list[dict[str, Any]]:
    """Poll the Firehose→S3 audit prefix until ``predicate(records)`` holds.

    LocalStack's 1s/1MiB buffer hints land records within ~1-2s; each call
    re-reads the whole (cumulative, per-test-cleared) prefix, so poll until
    enough records have flushed rather than sleeping a fixed time.
    """
    deadline = time.monotonic() + timeout
    records = _read_audit_s3_records(stream, timeout=0.1)
    while time.monotonic() < deadline:
        if predicate(records):
            return records
        await asyncio.sleep(poll_interval)
        records = _read_audit_s3_records(stream, timeout=0.1)
    return records


# ---------------------------------------------------------------------------
# Codex / Responses-API flow — per-frame audit + per-connection summary.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.slow
async def test_codex_responses_flow_emits_per_frame_audit_and_summary(
    docker_setup,
    clean_audit_pipeline,
) -> None:
    """End-to-end audit smoke for the Codex WS flow (ws-echo ``/v1/responses``).

    Asserts each server WS event lands in the response-body stream as its own
    frame record, and a per-connection ws-summary record lands with a matching
    server_text_frames count.
    """
    client_msg = json.dumps({"input": "smoke", "model": "gpt-4o-mini", "stream": True})

    server_frame_count = 0
    async with _ws_connect(
        f"{PROXY_WS_BASE}/v1/responses",
        additional_headers={"Authorization": _auth_header()},
        open_timeout=5,
    ) as ws:
        await ws.send(client_msg)
        for _ in range(20):  # bounded — mock sends at most ~5
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                break
            server_frame_count += 1
            if json.loads(msg).get("type") == "response.completed":
                break

    assert server_frame_count >= 3, (
        f"Expected at least 3 server frames (created + ≥1 delta + completed); "
        f"got {server_frame_count}"
    )

    # ``clean_audit_pipeline`` cleared the S3 audit prefix before this
    # test, so any ``response_body`` record under it is one of ours.
    def _response_body_records(rs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [r for r in rs if r.get("record_type") == "response_body"]

    resp_records = await _wait_for_s3_records(
        "response-body",
        lambda rs: len(_response_body_records(rs)) >= server_frame_count,
        timeout=20,
    )
    response_body_records = _response_body_records(resp_records)
    assert len(response_body_records) >= server_frame_count, (
        f"Per-frame audit missing: server sent {server_frame_count} frames, "
        f"saw {len(response_body_records)} response_body records"
    )

    request_ids = {r.get("request_id") for r in response_body_records}
    assert request_ids and all(request_ids), (
        f"Frame records missing or empty request_ids: {request_ids}"
    )
    assert len(request_ids) == 1, (
        f"Frame records span multiple request_ids (unexpected for a single "
        f"WS connection): {request_ids}"
    )
    our_req = next(iter(request_ids))

    summary_records = await _wait_for_s3_records(
        "ws-summary",
        lambda rs: any(r.get("record_type") == "ws_summary" for r in rs),
        timeout=20,
    )
    summaries = [r for r in summary_records if r.get("record_type") == "ws_summary"]
    assert summaries, "No ws_summary record was published"

    matching = [s for s in summaries if s.get("request_id") == our_req]
    assert matching, (
        f"ws_summary for our request_id {our_req!r} not found; "
        f"saw {len(summaries)} summaries with ids {[s.get('request_id') for s in summaries]}"
    )
    summary = matching[-1]
    assert summary["server_text_frames"] >= server_frame_count, (
        f"ws_summary undercount: server_text_frames={summary['server_text_frames']} "
        f"vs observed {server_frame_count}"
    )
    assert summary["client_text_frames"] >= 1, (
        f"ws_summary missing client frame: {summary['client_text_frames']}"
    )
