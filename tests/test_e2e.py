# disable line length check for this file because many strings are hard to break cleanly
# ruff: noqa: E501
import base64
import json
import time
import uuid

import pytest
import requests

# Import from conftest
from conftest import encode_base64, read_kinesis_records

_AUDIT_STREAMS = (
    "portunus-stream-request-headers",
    "portunus-stream-response-headers",
    "portunus-stream-response-body",
    "portunus-stream-metadata",
)


def _audit_record_counts() -> dict[str, int]:
    return {stream: len(read_kinesis_records(stream)) for stream in _AUDIT_STREAMS}


def test_envoy_health_endpoints_produce_no_audit_records(docker_setup):
    """``/ping`` and ``/healthz`` are Envoy's own replies and are not audited.

    ``/healthz`` is answered by the health_check filter ahead of ext_proc; if
    its route left ext_proc enabled, every probe would publish a response-only
    audit record with no request side to join it to.
    """
    before = _audit_record_counts()

    for _ in range(5):
        assert requests.get("http://localhost:8888/ping").status_code == 200
        assert requests.get("http://localhost:8888/healthz").status_code == 200
    # ext_proc publishes through the coalescing queue; give it time to flush.
    time.sleep(3)

    assert _audit_record_counts() == before


def test_custom_header_prefix_on_ping(docker_setup):
    """Test that PORTUNUS_HEADER_PREFIX=aisi-proxy is reflected in response headers.

    This doubles as a backwards-compatibility check for the original x-aisi-proxy-* headers.
    """
    response = requests.get("http://localhost:8888/ping")

    assert response.status_code == 200
    assert response.headers.get("x-aisi-proxy-ping") == "true"


@pytest.mark.parametrize(
    "docker_setup",
    ["xyz"],
    indirect=True,
)
def test_client_credential_headers_are_forwarded(
    api_key_prefix: str, api_key_header: str, docker_setup
):
    """Only the payload header changes; other credential-shaped headers pass through."""
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    response = requests.get(
        "http://localhost:8888/get",
        headers={
            api_key_header: f"{api_key_prefix}{payload}",
            "x-api-key": "client-supplied",
            "x-goog-api-key": "client-supplied",
            "api-key": "client-supplied",
            "x-not-a-credential": "kept",
        },
    )

    assert response.status_code == 200, response.content
    upstream_headers = {k.lower(): v for k, v in response.json()["headers"].items()}
    assert upstream_headers["authorization"] == api_key_prefix + docker_setup
    assert upstream_headers["x-not-a-credential"] == "kept"
    for name in ("x-api-key", "x-goog-api-key", "api-key"):
        assert upstream_headers[name] == "client-supplied"


def _wait_for_request_headers_record(request_id: str, timeout: float = 30) -> dict:
    """Poll the request-headers stream until the record for request_id appears."""
    deadline = time.time() + timeout
    while True:
        for record in read_kinesis_records("portunus-stream-request-headers"):
            if record.get("request_id") == request_id:
                return record
        if time.time() > deadline:
            pytest.fail(f"No request headers record for {request_id} in Kinesis")
        time.sleep(1)


@pytest.mark.parametrize(
    "docker_setup",
    ["xyz"],
    indirect=True,
)
def test_credential_headers_are_not_logged(
    api_key_prefix: str, api_key_header: str, docker_setup
):
    """The logged request headers carry no credential header, by name or value.

    The response's ``x-request-id`` is the key the audit records are filed
    under.
    """
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    marker = f"marker-{uuid.uuid4()}"
    response = requests.get(
        "http://localhost:8888/get",
        headers={
            api_key_header: f"{api_key_prefix}{payload}",
            "x-api-key": "client-supplied",
            "x-goog-api-key": "client-supplied",
            "api-key": "client-supplied",
            "x-test-marker": marker,
        },
    )
    assert response.status_code == 200, response.content

    record = _wait_for_request_headers_record(response.headers["x-request-id"])
    logged = {
        name.lower(): base64.b64decode(value).decode()
        for name, value in record["raw_headers"].items()
    }
    assert logged["x-test-marker"] == marker
    for name in ("authorization", "x-api-key", "x-goog-api-key", "api-key"):
        assert name not in logged
    for value in logged.values():
        assert docker_setup not in value
        assert payload not in value
        assert "client-supplied" not in value


@pytest.mark.parametrize("docker_setup", ["xyz"], indirect=True)
def test_client_supplied_request_id_is_not_trusted(
    api_key_prefix: str, api_key_header: str, docker_setup
):
    """A client cannot choose the id its audit records are filed under.

    A constant client-supplied ``x-request-id`` would collapse every record
    into one group (the 2026-07-02 joined-logs failure mode, made
    client-controllable). Envoy must mint its own.
    """
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    spoofed = f"spoof-{uuid.uuid4()}"
    marker = f"marker-{uuid.uuid4()}"
    response = requests.get(
        "http://localhost:8888/get",
        headers={
            api_key_header: f"{api_key_prefix}{payload}",
            "x-request-id": spoofed,
            "user-agent": marker,
        },
    )
    assert response.status_code == 200, response.content

    minted = response.headers["x-request-id"]
    assert minted != spoofed
    uuid.UUID(minted)
    record = _wait_for_request_headers_record(minted)
    logged = {
        name.lower(): base64.b64decode(value).decode()
        for name, value in record["raw_headers"].items()
    }
    assert logged["user-agent"] == marker
    assert all(
        record.get("request_id") != spoofed
        for record in read_kinesis_records("portunus-stream-request-headers")
    )


# Manually test with:
# curl -X POST http://localhost:8888/post -H "Authorization: Bearer eyJjcmVkZW50aWFscyI6eyJhY2Nlc3Nfa2V5X2lkIjoiQUtJQVRFU1QiLCJzZWNyZXRfYWNjZXNzX2tleSI6IlNFQ1JFVFRFU1QiLCJzZXNzaW9uX3Rva2VuIjoiVEVTVFRPS0VOIn0sInNlY3JldF9hcm4iOiJhcm46YXdzOnNlY3JldHNtYW5hZ2VyOnVzLWVhc3QtMToxMjM0NTY3ODkwMTI6c2VjcmV0OnRlc3Qtc2VjcmV0In0=" -H "Content-Type: application/json" -d '{"key3":   "value3"   , "key1":"value1","key2" : "value2" }' # noqa: E501
@pytest.mark.parametrize(
    "docker_setup",
    [
        json.dumps(
            {
                "secret": "xyz",
                "signing_key": {
                    "kms_key_arn": "arn:aws:kms:eu-west-2:000000000000:alias/test-key",
                    "provider_id": "signingkey_1234abcd",
                },
            }
        )
    ],
    indirect=True,
)
def test_secret_with_legacy_signing_key_is_forwarded_unsigned(
    api_key_prefix: str, api_key_header: str, docker_setup: str
):
    """Secrets written for the removed request-signing feature still work.

    The signing_key field is ignored: the request is forwarded with the API key
    and none of the RFC 9421 headers.
    """
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    response = requests.post(
        "http://localhost:8888/post",
        headers={api_key_header: f"{api_key_prefix}{payload}"},
        data='{"key3": "value3", "key1": "value1", "key2": "value2"}',
    )

    assert response.status_code == 200, response.content
    headers = response.json()["headers"]
    assert headers["Authorization"] == api_key_prefix + "xyz"
    assert "Content-Digest" not in headers
    assert "Signature" not in headers
    assert "Signature-Input" not in headers


def test_401_passthrough_for_missing_credentials(
    api_key_prefix: str, api_key_header: str, docker_setup
):
    """Test that 401 errors from Portunus are passed through the proxy.

    This verifies that when Portunus returns a 401 (e.g., for missing/invalid
    credentials), the proxy correctly passes this through to the client.

    Note: LocalStack doesn't validate AWS credentials like real AWS does,
    so we test with missing credentials to trigger validation errors.
    """
    payload_data = {
        "credentials": {
            "access_key_id": "",
            "secret_access_key": "",
        },
        "secret_arn": "arn:aws:secretsmanager:eu-west-2:000000000000:secret:test-api-key",
    }
    payload = encode_base64(payload_data)

    response = requests.get(
        "http://localhost:8888/get",
        headers={api_key_header: f"{api_key_prefix}{payload}"},
    )

    assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    error_data = response.json()
    assert "error" in error_data
    assert "message" in error_data["error"]

    # Verify the proxy error header uses the custom prefix (aisi-proxy)
    assert response.headers.get("x-aisi-proxy-error") == "true"


def test_error_response_contains_trace_id(
    api_key_prefix: str, api_key_header: str, docker_setup: str
):
    """Error responses must carry a correlatable debug ID.

    Accept either ``request_id`` (current) or the legacy ``x_amzn_trace_id``
    field — the contract is presence, not field name.
    """
    response = requests.get(
        "http://localhost:8888/get",
        headers={api_key_header: f"{api_key_prefix}invalid_payload"},
    )

    # Should get an error response
    assert response.status_code in (401, 500), response.content

    error_data = response.json()
    assert "error" in error_data
    assert (
        "x_amzn_trace_id" in error_data["error"] or "request_id" in error_data["error"]
    ), error_data

    # And a debug ID header is present so operators can correlate without
    # reading the body.
    assert (
        "X-Amzn-Trace-Id" in response.headers
        or "x-portunus-debug-id" in response.headers
    ), dict(response.headers)
