# ruff: noqa: E501, E402
"""End-to-end tests for WebSocket relay through Envoy -> Portunus.

These tests require Docker Compose to be running with the ws-echo container.
They test the full WS flow: client -> Envoy -> Portunus WS -> ws-echo upstream,
including bidirectional relay and per-message Firehose logging.
"""

import asyncio
import base64
import gzip
import json
import os
import subprocess
import sys
import time

import pytest
import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatusCode

# Add portunus to the Python path
portunus_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus")
if portunus_path not in sys.path:
    sys.path.append(portunus_path)

# Disable X-Ray SDK for tests
os.environ["AWS_XRAY_SDK_ENABLED"] = "false"
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")

from conftest import encode_base64

# Envoy routes /ws/* to Portunus, which relays to ws-echo upstream.
PROXY_WS_URL = "ws://localhost:8888/ws/echo"


@pytest.fixture(scope="module")
def ws_docker_setup():
    """Ensure Docker Compose is running for WS tests."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Status}}", "portunus"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and "running" in result.stdout:
        yield
        return

    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--build", "--wait"],
        capture_output=True,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )
    if result.returncode != 0:
        pytest.skip(f"Docker Compose failed to start: {result.stderr.decode()}")
    time.sleep(5)
    yield


def make_auth_header(api_key_prefix="Bearer "):
    """Create a valid auth header for WS tests."""
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    return f"{api_key_prefix}{payload}"


def get_close_code(exc: ConnectionClosed) -> int:
    """Extract close code from ConnectionClosed, handling v12 and v13 API."""
    if hasattr(exc, "rcvd") and exc.rcvd is not None:
        return exc.rcvd.code
    return exc.code  # type: ignore[attr-defined]


def read_firehose_records(stream_name: str) -> list[dict]:
    """Read all records that Firehose has flushed to S3 in localstack.

    Firehose buffers records and writes them to S3 as GZIP'd JSON, one
    record per line. We list every object under ``logs/<prefix>/`` and
    parse the contents.

    The ``stream_name`` is the Firehose delivery-stream name, which by
    convention matches the S3 prefix segment (e.g. the delivery stream
    ``portunus-stream-request-body`` writes to ``logs/request-body/``).
    """
    prefix_segment = stream_name.removeprefix("portunus-stream-")
    s3_prefix = f"logs/{prefix_segment}/"
    bucket = "portunus-logs-local"

    list_result = subprocess.run(
        [
            "docker",
            "exec",
            "localstack-main",
            "awslocal",
            "s3api",
            "list-objects-v2",
            "--bucket",
            bucket,
            "--prefix",
            s3_prefix,
            "--region",
            "eu-west-2",
        ],
        capture_output=True,
        text=True,
    )
    if list_result.returncode != 0 or not list_result.stdout.strip():
        return []

    try:
        listing = json.loads(list_result.stdout)
    except json.JSONDecodeError:
        return []

    records: list[dict] = []
    for obj in listing.get("Contents", []) or []:
        key = obj["Key"]
        get_result = subprocess.run(
            [
                "docker",
                "exec",
                "localstack-main",
                "bash",
                "-lc",
                f"awslocal s3 cp s3://{bucket}/{key} - --region eu-west-2 | base64",
            ],
            capture_output=True,
            text=True,
        )
        if get_result.returncode != 0:
            continue
        raw = base64.b64decode(get_result.stdout)
        try:
            payload = gzip.decompress(raw)
        except (OSError, EOFError):
            # LocalStack may flush uncompressed for small buffers
            payload = raw
        # Firehose concatenates records as newline-delimited JSON
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


@pytest.mark.slow
class TestWebSocketAuth:
    """Test WebSocket authentication through Envoy -> Portunus."""

    @pytest.mark.asyncio
    async def test_ws_without_auth_rejected(self, ws_docker_setup):
        """WS connection without auth header is rejected by Portunus."""
        try:
            ws = await websockets.connect(PROXY_WS_URL, open_timeout=5)
            try:
                await asyncio.wait_for(ws.recv(), timeout=3)
                pytest.fail("Expected close, got message")
            except ConnectionClosed as e:
                assert get_close_code(e) in (4001, 4003)
        except InvalidStatusCode as e:
            assert e.status_code in (400, 401, 403)

    @pytest.mark.asyncio
    async def test_ws_with_invalid_auth_rejected(self, ws_docker_setup):
        """WS connection with invalid auth payload is rejected."""
        try:
            ws = await websockets.connect(
                PROXY_WS_URL,
                extra_headers={"Authorization": "Bearer invalid_payload"},
                open_timeout=5,
            )
            try:
                await asyncio.wait_for(ws.recv(), timeout=3)
                pytest.fail("Expected close, got message")
            except ConnectionClosed as e:
                assert get_close_code(e) in (4001, 4003)
        except InvalidStatusCode as e:
            assert e.status_code in (401, 403)


@pytest.mark.slow
class TestWebSocketRelay:
    """Test full bidirectional WebSocket relay through Envoy -> Portunus -> ws-echo."""

    @pytest.mark.asyncio
    async def test_message_echo(self, ws_docker_setup):
        """Messages sent to the relay are echoed back by ws-echo upstream."""
        auth_header = make_auth_header()
        ws = await websockets.connect(
            PROXY_WS_URL,
            extra_headers={"Authorization": auth_header},
            open_timeout=5,
        )
        try:
            # Send and receive echo
            await ws.send("hello portunus")
            echo = await asyncio.wait_for(ws.recv(), timeout=5)
            assert echo == "hello portunus"

            # Second message
            await ws.send("second message")
            echo2 = await asyncio.wait_for(ws.recv(), timeout=5)
            assert echo2 == "second message"
        finally:
            await ws.close()

    @pytest.mark.asyncio
    async def test_messages_logged_to_firehose(self, ws_docker_setup):
        """WS messages appear in the existing request-body/response-body streams."""
        auth_header = make_auth_header()
        ws = await websockets.connect(
            PROXY_WS_URL,
            extra_headers={"Authorization": auth_header},
            open_timeout=5,
        )
        try:
            # Send a unique message so we can find it in Firehose's S3 output
            test_msg = f"firehose-test-{time.time()}"
            await ws.send(test_msg)
            await asyncio.wait_for(ws.recv(), timeout=5)
        finally:
            await ws.close()

        # Firehose buffers records before flushing to S3. The LocalStack
        # init script configures a 10s buffer interval, plus we run a 1s
        # per-PutRecord throttle in publish_service when an endpoint URL
        # is set. Wait long enough for the buffer to flush.
        await asyncio.sleep(15)

        # Client messages go to request-body stream
        req_records = read_firehose_records("portunus-stream-request-body")
        assert len(req_records) > 0, "No records found in request-body stream"

        # Find our test message in request-body
        client_msgs = [
            r
            for r in req_records
            if r["record_type"] == "request_body"
            and base64.b64decode(r["body"]).decode() == test_msg
        ]
        assert len(client_msgs) >= 1, (
            f"Test message '{test_msg}' not found in request-body stream. "
            f"Got {len(req_records)} records total."
        )

        # Verify record uses existing RequestBodyRecord structure
        record = client_msgs[0]
        assert record["chunk_id"] == 0
        assert record["num_chunks"] == 1
        assert "request_id" in record
        assert "timestamp" in record

        # Echo response should appear in response-body stream
        resp_records = read_firehose_records("portunus-stream-response-body")
        echo_msgs = [
            r
            for r in resp_records
            if r["record_type"] == "response_body"
            and base64.b64decode(r["body"]).decode() == test_msg
        ]
        assert (
            len(echo_msgs) >= 1
        ), f"Echo of '{test_msg}' not found in response-body stream."

    @pytest.mark.asyncio
    async def test_metadata_published_on_ws_connect(self, ws_docker_setup):
        """Metadata record is published to Firehose when WS connection is established."""
        auth_header = make_auth_header()
        ws = await websockets.connect(
            PROXY_WS_URL,
            extra_headers={"Authorization": auth_header},
            open_timeout=5,
        )
        await ws.close()

        # Wait for Firehose buffer flush (10s interval + slack)
        await asyncio.sleep(15)

        records = read_firehose_records("portunus-stream-metadata")
        metadata_records = [r for r in records if r["record_type"] == "metadata"]
        assert len(metadata_records) > 0, "No metadata records found"

        # Verify structure of a metadata record
        record = metadata_records[-1]
        assert "request_id" in record
        assert "account_id" in record
        assert "timestamp" in record


@pytest.mark.slow
class TestEnvoyWebSocketRouting:
    """Test that Envoy correctly routes WS upgrades to Portunus."""

    @pytest.mark.asyncio
    async def test_envoy_ws_route_reaches_portunus(self, ws_docker_setup):
        """Auth rejection (not 404/502) proves the WS route reaches Portunus."""
        try:
            ws = await websockets.connect(
                PROXY_WS_URL,
                extra_headers={"Authorization": "Bearer invalid"},
                open_timeout=5,
            )
            try:
                await asyncio.wait_for(ws.recv(), timeout=3)
            except ConnectionClosed as e:
                assert (
                    get_close_code(e) == 4001
                ), f"Unexpected close code: {get_close_code(e)}"
        except InvalidStatusCode as e:
            assert e.status_code in (
                401,
                403,
            ), f"Expected auth rejection, got {e.status_code}"

    @pytest.mark.asyncio
    async def test_non_ws_path_still_routes_to_target(self, ws_docker_setup):
        """Regular HTTP to /ping still goes through Lua to httpbun."""
        import requests

        response = requests.get("http://localhost:8888/ping")
        assert response.status_code == 200
