# ruff: noqa: E501, E402
"""Audit-pipeline smoke tests for the gRPC ext_authz/ext_proc model.

Drives realistic client flows (signing-bearing HTTP POST, Codex-shaped
Responses-API WS stream) through Portunus and asserts the expected audit
records land in LocalStack S3 — the pipeline aisitok consumes. Transport-level
behaviour lives in ``test_ws_proxy_behaviour.py`` / ``test_http_proxy_behaviour.py``.

Run with the docker-compose stack up. Marked ``slow`` so CI lint/type-check skip them.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import requests

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))
os.environ["AWS_XRAY_SDK_ENABLED"] = "false"
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")

from conftest import _read_audit_s3_records, encode_base64  # noqa: E402

# Import the ws-client used by the behaviour suite so we're on the
# same client surface (additional_headers, asyncio API).
from websockets.asyncio.client import connect as _ws_connect  # noqa: E402

PROXY_HTTP = "http://localhost:8888"
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


# ---------------------------------------------------------------------------
# Signing flow — audited request headers carry Content-Digest / Signature.
# ---------------------------------------------------------------------------


def _load_anthropic_signing_vector() -> dict[str, Any]:
    test_vector_path = (
        Path(__file__).parent.parent / "data" / "anthropic_signing_test_cases.json"
    )
    with open(test_vector_path) as f:
        cases = json.load(f)
    return next(
        c for c in cases["test_vectors"] if c["algorithm"] == "ecdsa-p256-sha256"
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "docker_setup",
    [
        json.dumps(
            {
                "secret": "sk-ant-api03-test-key-000000000000",
                "signing_key": {
                    "kms_key_arn": "arn:aws:kms:eu-west-2:000000000000:alias/test-key",
                    "provider_id": "signingkey_12345",
                },
            }
        )
    ],
    indirect=True,
)
def test_signed_request_publishes_digest_and_signature_headers_to_s3(
    api_key_prefix: str,
    api_key_header: str,
    docker_setup: str,
    clean_audit_pipeline,
):
    """Signing-pass smoke: S3 audit carries Content-Digest + Signature headers.

    Complements ``test_e2e_signing.py`` (upstream-seen headers); this validates
    the same headers reach the Firehose→S3 audit pipeline, catching publish-side
    regressions the wire-level check misses.
    """
    vector = _load_anthropic_signing_vector()
    body = vector["request"]["body"]
    credentials = encode_base64({"credentials": {}, "secret_arn": ""})

    resp = requests.post(
        f"{PROXY_HTTP}/post",
        headers={
            api_key_header: f"{api_key_prefix}{credentials}",
            "Content-Type": "application/json",
        },
        data=body,
    )
    assert resp.status_code == 200, resp.content

    def _header_records() -> list[dict[str, Any]]:
        return [
            r
            for r in _read_audit_s3_records("request-headers", timeout=0.1)
            if r.get("record_type") == "request_headers"
        ]

    # Poll briefly — publish is async-fire-and-forget through the publish
    # queue, then Firehose buffers ~1-2s before the record lands on S3.
    deadline = time.monotonic() + 20
    header_records = _header_records()
    while time.monotonic() < deadline and not header_records:
        time.sleep(0.5)
        header_records = _header_records()

    assert header_records, "No request_headers record was published for this test"

    def _has_signing_headers(rec: dict[str, Any]) -> bool:
        raw = rec.get("raw_headers", {})
        # Header keys are case-insensitive on the wire; the publisher
        # lowercases. Values are base64-encoded.
        return "content-digest" in {k.lower() for k in raw.keys()} and "signature" in {
            k.lower() for k in raw.keys()
        }

    signed = [r for r in header_records if _has_signing_headers(r)]
    assert signed, (
        "No request_headers record carries both content-digest and signature; "
        f"saw {len(header_records)} records with keys: "
        f"{[sorted(r.get('raw_headers', {}).keys()) for r in header_records]}"
    )

    record = signed[-1]
    raw_headers = {k.lower(): v for k, v in record["raw_headers"].items()}
    decoded_digest = base64.b64decode(raw_headers["content-digest"]).decode("utf-8")
    assert decoded_digest == vector["expected_values"]["content_digest"], (
        f"Content-Digest in the audit record differs from upstream-seen value: "
        f"{decoded_digest} vs {vector['expected_values']['content_digest']}"
    )
    decoded_sig = base64.b64decode(raw_headers["signature"]).decode("utf-8")
    assert re.match(r"^sig1=:[A-Za-z0-9+/=]+:$", decoded_sig), (
        f"Signature in the audit record malformed: {decoded_sig!r}"
    )
