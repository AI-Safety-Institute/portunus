# ruff: noqa: E501, E402
"""Audit-pipeline smoke tests for the gRPC ext_authz/ext_proc model.

Drives realistic client flows (signing-bearing HTTP POST, Codex-shaped
Responses-API WS stream) through Portunus and asserts the expected
Kinesis records land in LocalStack. The transport-level behaviour tests
live in ``test_ws_proxy_behaviour.py`` / ``test_http_proxy_behaviour.py``;
this file's job is the audit arm — the pipeline that aisitok consumes.

These are the gating smoke tests for the blue/green cutover: a
regression in the publish queue, frame observation, or signing-pass
data path surfaces here as a missing or malformed record.

Run with the docker-compose stack up (see ``test_ws_proxy_behaviour.py``
for setup). Marked ``slow`` so CI lint/type-check skip them.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import requests

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))
os.environ["AWS_XRAY_SDK_ENABLED"] = "false"
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")

from conftest import encode_base64  # noqa: E402

# Import the ws-client used by the behaviour suite so we're on the
# same client surface (additional_headers, asyncio API).
from websockets.asyncio.client import connect as _ws_connect  # noqa: E402

PROXY_HTTP = "http://localhost:8888"
PROXY_WS_BASE = "ws://localhost:8888"


def _auth_header(api_key_prefix: str = "Bearer ") -> str:
    return f"{api_key_prefix}{encode_base64({'credentials': {}, 'secret_arn': ''})}"


def _read_kinesis_records(stream_name: str) -> list[dict[str, Any]]:
    """Drain a Kinesis stream from LocalStack, deserialising each record.

    Returns one decoded JSON object per record. Safe to call repeatedly;
    Kinesis returns TRIM_HORIZON onward each time, so tests get the full
    history regardless of how many records they're after.
    """
    shard_result = subprocess.run(
        [
            "docker",
            "exec",
            "localstack-main",
            "awslocal",
            "kinesis",
            "get-shard-iterator",
            "--stream-name",
            stream_name,
            "--shard-id",
            "shardId-000000000000",
            "--shard-iterator-type",
            "TRIM_HORIZON",
            "--region",
            "eu-west-2",
            "--query",
            "ShardIterator",
            "--output",
            "text",
        ],
        capture_output=True,
        text=True,
    )
    if shard_result.returncode != 0:
        return []
    shard_iterator = shard_result.stdout.strip()
    records_result = subprocess.run(
        [
            "docker",
            "exec",
            "localstack-main",
            "awslocal",
            "kinesis",
            "get-records",
            "--shard-iterator",
            shard_iterator,
            "--region",
            "eu-west-2",
        ],
        capture_output=True,
        text=True,
    )
    if records_result.returncode != 0:
        return []
    response = json.loads(records_result.stdout)
    out: list[dict[str, Any]] = []
    for r in response.get("Records", []):
        out.append(json.loads(base64.b64decode(r["Data"])))
    return out


async def _wait_for_records(
    stream_name: str,
    predicate,
    *,
    timeout: float = 15.0,
    poll_interval: float = 0.5,
) -> list[dict[str, Any]]:
    """Poll a Kinesis stream until ``predicate(records)`` returns truthy.

    LocalStack Kinesis lags 0.5–2s behind put_records under load; polling
    instead of a fixed sleep keeps the suite fast without flaking on slow
    runners.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        records = _read_kinesis_records(stream_name)
        if predicate(records):
            return records
        await asyncio.sleep(poll_interval)
    return _read_kinesis_records(stream_name)


# ---------------------------------------------------------------------------
# Codex / Responses-API flow — per-frame audit + per-connection summary.
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason="Reads from LocalStack Kinesis Data Streams. After the Firehose "
    "direct-PUT migration, audit records flow to Firehose → S3 with a "
    "~60s buffer (too slow for a smoke test). Needs a "
    "LocalStack-Firehose flush-then-S3 verification path; tracked as a "
    "follow-up."
)
@pytest.mark.asyncio
@pytest.mark.slow
async def test_codex_responses_flow_emits_per_frame_audit_and_summary(
    docker_setup,
    clean_kinesis_streams,
) -> None:
    """End-to-end audit-pipeline smoke for the Codex WS flow.

    Drives ws-echo's ``/v1/responses`` mock, which emits a Responses-API
    event stream. Asserts:
      * Each server-emitted WS event lands in the response-body Kinesis
        stream as its own frame audit record.
      * A per-connection summary record lands in the ws-summary stream
        with a matching server_text_frames count.
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

    # ``clean_kinesis_streams`` reset the streams before this test, so any
    # ``response_body`` record on the stream is one of ours.
    def _response_body_records(rs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [r for r in rs if r.get("record_type") == "response_body"]

    resp_records = await _wait_for_records(
        "portunus-stream-response-body",
        lambda rs: len(_response_body_records(rs)) >= server_frame_count,
        timeout=20,
    )
    response_body_records = _response_body_records(resp_records)
    assert len(response_body_records) >= server_frame_count, (
        f"Per-frame audit missing: server sent {server_frame_count} frames, "
        f"saw {len(response_body_records)} response_body records"
    )

    request_ids = {r.get("request_id") for r in response_body_records}
    assert request_ids and all(
        request_ids
    ), f"Frame records missing or empty request_ids: {request_ids}"
    assert len(request_ids) == 1, (
        f"Frame records span multiple request_ids (unexpected for a single "
        f"WS connection): {request_ids}"
    )
    our_req = next(iter(request_ids))

    summary_records = await _wait_for_records(
        "portunus-stream-ws-summary",
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
    assert (
        summary["client_text_frames"] >= 1
    ), f"ws_summary missing client frame: {summary['client_text_frames']}"


# ---------------------------------------------------------------------------
# Signing flow — request headers in Kinesis carry Content-Digest / Signature.
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


@pytest.mark.skip(
    reason="Reads from Kinesis Data Streams via LocalStack, but the audit "
    "pipeline now uses Firehose direct-PUT → S3 with default ~60s buffer "
    "(too slow for a smoke test). Needs a LocalStack-Firehose flush-then-S3 "
    "verification path; tracked as a follow-up."
)
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
def test_signed_request_publishes_digest_and_signature_headers_to_kinesis(
    api_key_prefix: str,
    api_key_header: str,
    docker_setup: str,
    clean_kinesis_streams,
):
    """Signing-pass smoke: Kinesis carries Content-Digest + Signature headers.

    Complements ``test_e2e_signing.py``, which validates the headers as
    seen by the upstream. This validates the same headers reach the
    audit pipeline — a publish-side regression in the signing-pass flow
    surfaces here, not in the wire-level check.
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
            for r in _read_kinesis_records("portunus-stream-request-headers")
            if r.get("record_type") == "request_headers"
        ]

    # Poll briefly — Kinesis publish is async-fire-and-forget through the
    # publish queue.
    deadline = time.monotonic() + 15
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
        f"Content-Digest in Kinesis differs from upstream-seen value: "
        f"{decoded_digest} vs {vector['expected_values']['content_digest']}"
    )
    decoded_sig = base64.b64decode(raw_headers["signature"]).decode("utf-8")
    assert re.match(
        r"^sig1=:[A-Za-z0-9+/=]+:$", decoded_sig
    ), f"Signature in Kinesis malformed: {decoded_sig!r}"
