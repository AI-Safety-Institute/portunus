# disable line length check for this file because many strings are hard to break cleanly
# ruff: noqa: E501
"""E2E tests for request signing with Anthropic test vectors.

These tests verify the complete request signing flow including:
1. Byte-level Content-Digest computation matching Anthropic's expectations
2. Proper formatting of Signature and Signature-Input headers
3. KMS integration via LocalStack
"""

import json
import re
from pathlib import Path

import pytest
import requests

# Import from conftest
from conftest import encode_base64


def load_anthropic_test_cases():
    """Load Anthropic signing test vectors."""
    test_vector_path = (
        Path(__file__).parent.parent / "data" / "anthropic_signing_test_cases.json"
    )
    with open(test_vector_path) as f:
        return json.load(f)


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
def test_e2e_request_signing_with_anthropic_test_vector(
    api_key_prefix: str,
    api_key_header: str,
    docker_setup: str,
):
    """
    E2E test for request signing using Anthropic test vector data.

    This test verifies that:
    1. Byte-level Content-Digest matches expected value from test vectors
    2. Signature and Signature-Input headers are properly formatted

    Note: We cannot verify the exact signature matches the test vector because
    LocalStack generates its own key. However, verifying Content-Digest matches
    proves that byte-level digest computation works correctly.
    """
    # Load test vectors
    test_cases = load_anthropic_test_cases()
    ecdsa_test_case = next(
        tc
        for tc in test_cases["test_vectors"]
        if tc["algorithm"] == "ecdsa-p256-sha256"
    )

    # Get the raw request body string from the test vector
    # This is already in the exact format that should be digested
    request_body = ecdsa_test_case["request"]["body"]
    credentials = encode_base64({"credentials": {}, "secret_arn": ""})

    # Use 'data' instead of 'json' to send the raw string without re-serialization
    response = requests.post(
        "http://localhost:8888/post",
        headers={
            api_key_header: f"{api_key_prefix}{credentials}",
            "Content-Type": "application/json",
        },
        data=request_body,
    )

    assert response.status_code == 200, f"Request failed: {response.content.decode()}"

    response_data = response.json()

    # Verify Content-Digest header was added and matches expected
    assert "Content-Digest" in response_data["headers"]
    expected_digest = ecdsa_test_case["expected_values"]["content_digest"]
    actual_digest = response_data["headers"]["Content-Digest"]

    assert actual_digest == expected_digest, (
        f"Content-Digest mismatch!\n"
        f"Expected: {expected_digest}\n"
        f"Actual:   {actual_digest}\n"
        f"The byte-level digest computation does not match Anthropic's expectations."
    )

    # Verify Signature-Input header is properly formatted
    assert "Signature-Input" in response_data["headers"]
    signature_input = response_data["headers"]["Signature-Input"]

    assert re.match(
        r'^sig1=\("@method" "@target-uri" "content-digest" "content-type" "x-api-key"\);created=\d+;keyid="signingkey_12345";alg="ecdsa-p256-sha256"$',
        signature_input,
    ), f"Signature-Input format incorrect: {signature_input}"

    # Verify signature is present and properly formatted
    assert "Signature" in response_data["headers"]
    signature = response_data["headers"]["Signature"]

    assert signature.startswith("sig1=:"), "Signature should start with 'sig1=:'"
    assert signature.endswith(":"), "Signature should end with ':'"

    signature_b64 = signature[len("sig1=:") : -1]
    # Note: We cannot verify the signature matches the test vector exactly because
    # LocalStack cannot import asymmetric keys.
    # The portunus unit tests have an exact signature verification with mocked KMS.
    assert len(signature_b64) > 0, "Signature should not be empty"
