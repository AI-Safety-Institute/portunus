# disable line length check for this file because many strings are hard to break cleanly
# ruff: noqa: E501
import json
import re

import pytest
import requests

# Import from conftest
from conftest import encode_base64


def test_custom_header_prefix_on_ping(docker_setup):
    """Test that PORTUNUS_HEADER_PREFIX=aisi-proxy is reflected in response headers.

    This doubles as a backwards-compatibility check for the original x-aisi-proxy-* headers.
    """
    response = requests.get("http://localhost:8888/ping")

    assert response.status_code == 200
    assert response.headers.get("x-aisi-proxy-ping") == "true"


# NOTE: The following tests were removed because they are covered by the
# behaviour corpus in tests/test_behaviours.py — duplicates were dropped
# rather than maintained in two places:
#   - test_request_without_payload
#       → request_without_authorization_header_is_rejected
#   - test_request_with_invalid_payload
#       → request_with_malformed_base64_payload_is_rejected
#   - test_auth_fails_when_target_host_mismatches
#       → secret_with_mismatching_host_is_rejected_with_403
#   - test_auth_succeeds_with_plain_text_key
#       → valid_request_with_plaintext_secret_reaches_upstream
# The tests that remain in this file cover behaviours not yet in the
# corpus (custom response-header prefix, request signing, error-response
# diagnostics) — migrate into the corpus when shapes align.


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
@pytest.mark.xfail(
    reason=(
        "Request signing needs Content-Digest computed over the request body, "
        "which requires either ext_authz with_request_body=true (buffering) or "
        "a body-side hook in ext_proc that can mutate request headers before "
        "they reach upstream. The Lua filter computed this inline; the gRPC "
        "model needs a redesign. Tracked as a follow-up."
    ),
    strict=False,
)
def test_request_signs_correctly(
    api_key_prefix: str, api_key_header: str, docker_setup: str
):
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    response = requests.post(
        "http://localhost:8888/post",
        headers={api_key_header: f"{api_key_prefix}{payload}"},
        data='{"key3": "value3", "key1": "value1", "key2": "value2"}',
    )

    assert response.status_code == 200, response.content
    response_data = response.json()
    assert (
        response_data["headers"]["Content-Digest"]
        == "sha-256=:qEP36VVnZHuLid25my9AS/iuzXwq1eIKa5at9nJrcZc=:"
    )
    # cannot easily test exact signature as:
    # 1. signature changes with timestamp & we're running the app via docker here
    # 2. we generate a new localstack KMS key on each test run
    assert "sig1=:" in response_data["headers"]["Signature"]
    assert len(response_data["headers"]["Signature"]) > 32
    assert (
        re.match(
            r'^sig1=\("@method" "@target-uri" "content-digest" "content-type" "x-api-key"\);created=\d+;keyid="signingkey_1234abcd";alg="ecdsa-p256-sha256"$',
            response_data["headers"]["Signature-Input"],
        )
        is not None
    )


def test_request_without_signing(
    api_key_prefix: str, api_key_header: str, docker_setup: str
):
    """Test that requests don't get Signature header when signing is disabled."""
    payload = encode_base64({"credentials": {}, "secret_arn": ""})
    response = requests.post(
        "http://localhost:8888/post",
        headers={api_key_header: f"{api_key_prefix}{payload}"},
        json={"key3": "value3", "key1": "value1", "key2": "value2"},
    )

    assert response.status_code == 200, response.content
    response_data = response.json()

    # Verify /authorise endpoint was hit
    assert "Authorization" in response_data["headers"]
    assert response_data["headers"]["Authorization"] == api_key_prefix + docker_setup

    # Verify that no signing headers are present when signing is disabled
    assert "Signature" not in response_data["headers"]
    assert "Signature-Input" not in response_data["headers"]


def test_401_passthrough_for_missing_credentials(
    api_key_prefix: str, api_key_header: str, docker_setup
):
    """Test that 401 errors from Portunus are passed through the Lua proxy.

    This verifies that when Portunus returns a 401 (e.g., for missing/invalid
    credentials), the Lua proxy correctly passes this through to the client.

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
    """Test that error responses contain a trace ID for debugging.

    This verifies that when auth fails, the error response includes
    a trace ID that can be used for debugging and correlation.
    """
    response = requests.get(
        "http://localhost:8888/get",
        headers={api_key_header: f"{api_key_prefix}invalid_payload"},
    )

    # Should get an error response
    assert response.status_code in (401, 500), response.content

    error_data = response.json()
    assert "error" in error_data

    # Verify trace ID is present in response
    assert "x_amzn_trace_id" in error_data["error"]

    # Verify trace ID header is also set
    assert "X-Amzn-Trace-Id" in response.headers
