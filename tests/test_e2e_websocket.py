# ruff: noqa: E501, E402
"""End-to-end tests for WebSocket relay through Envoy -> Portunus.

These tests require Docker Compose to be running with the ws-echo container.
They test the full WS flow: client -> Envoy -> Portunus WS -> ws-echo upstream,
including bidirectional relay and per-message Kinesis logging.
"""

import asyncio
import base64
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

# ws-echo serves on any path — Envoy routes WS upgrades to Portunus
# based on the Upgrade header, and Portunus forwards the path to upstream.
PROXY_WS_URL = "ws://localhost:8888/echo"


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


def read_kinesis_records(stream_name: str) -> list[dict]:
    """Read all records from a Kinesis stream in localstack."""
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
    records = []
    for r in response.get("Records", []):
        data = base64.b64decode(r["Data"])
        records.append(json.loads(data))
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
    async def test_messages_logged_to_kinesis(self, ws_docker_setup):
        """WS messages appear in the existing request-body/response-body streams."""
        auth_header = make_auth_header()
        ws = await websockets.connect(
            PROXY_WS_URL,
            extra_headers={"Authorization": auth_header},
            open_timeout=5,
        )
        try:
            # Send a unique message so we can find it in Kinesis
            test_msg = f"kinesis-test-{time.time()}"
            await ws.send(test_msg)
            await asyncio.wait_for(ws.recv(), timeout=5)
        finally:
            await ws.close()

        # Wait for fire-and-forget logging tasks to complete
        # LocalStack Kinesis has a 1s throttle per publish in local mode
        await asyncio.sleep(8)

        # Client messages go to request-body stream
        req_records = read_kinesis_records("portunus-stream-request-body")
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
        resp_records = read_kinesis_records("portunus-stream-response-body")
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
        """Metadata record is published to Kinesis when WS connection is established."""
        auth_header = make_auth_header()
        ws = await websockets.connect(
            PROXY_WS_URL,
            extra_headers={"Authorization": auth_header},
            open_timeout=5,
        )
        await ws.close()

        # Wait for publish
        await asyncio.sleep(4)

        records = read_kinesis_records("portunus-stream-metadata")
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
