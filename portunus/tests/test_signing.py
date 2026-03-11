# disable line length check for this file because many strings are hard to break cleanly
# ruff: noqa: E501
import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import boto3
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from freezegun import freeze_time
from moto import mock_aws

from portunus.models import AwsCredentials, SigningKey
from portunus.services.signing_service import (
    SignableRequest,
    _build_signature_params_and_base,
    sign_request,
)


@pytest.fixture()
def anthropic_key_id() -> str:
    return "signingkey_1234abcd"


@pytest.fixture()
def kms_key_arn() -> str:
    return "arn:aws:kms:eu-west-2:000000000000:alias/test-key"


@pytest.fixture()
def signable_request() -> SignableRequest:
    return SignableRequest.model_validate(
        {
            "type": "anthropic",
            "url": "https://api.anthropic.com/v1/messages",
            "method": "POST",
            "content_type": "application/json",
            # SHA-256 digest of the byte string:
            # {"max_tokens":1024,"messages":[{"role": "user", "content": "Hello, world"}],"model": "claude-sonnet-4-20250514"}
            "content_digest": "sha-256=:TBejC824Zkyj+msrl4D0xulzq7c91UhOJBeERaWGnd0=:",
        }
    )


@pytest.fixture()
def signing_key(anthropic_key_id: str, kms_key_arn: str) -> SigningKey:
    return SigningKey(
        provider_id=anthropic_key_id,
        kms_key_arn=kms_key_arn,
    )


@mock_aws
def test_sign_request(signable_request: SignableRequest, signing_key: SigningKey):
    # Create a KMS key using moto
    kms = boto3.client("kms", region_name="eu-west-2")
    key = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256")
    kms.create_alias(
        AliasName="alias/test-key", TargetKeyId=key["KeyMetadata"]["KeyId"]
    )

    # Create mock user credentials
    user_credentials = AwsCredentials(
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token="FakeSessionToken123",
    )

    headers = sign_request(
        signable_request,
        signing_key,
        api_key="token123",
        user_credentials=user_credentials,
    )

    # Check that headers are properly formatted
    assert "Signature" in headers
    assert "Signature-Input" in headers

    # Signature should be in the format sig1=:base64_signature:
    assert headers["Signature"].startswith("sig1=:")
    assert headers["Signature"].endswith(":")

    # Signature-Input should match expected pattern
    assert (
        re.match(
            r'^sig1=\("@method" "@target-uri" "content-digest" "content-type" "x-api-key"\);created=\d+;keyid="signingkey_1234abcd";alg="ecdsa-p256-sha256"$',
            headers["Signature-Input"],
        )
        is not None
    )


def test_build_signature_params_and_base(signing_key: SigningKey) -> None:
    api_key = "token123"
    # Sep 23 2025 11:57:25 GMT+0000
    created: int = 1758628645
    algorithm: str = "ecdsa-p256-sha256"
    req = SignableRequest.model_validate(
        {
            "type": "anthropic",
            "url": "https://api.anthropic.com/v1/messages",
            "method": "POST",
            "content_type": "application/json",
            # SHA-256 digest of the byte string:
            # {"max_tokens":1024,"messages":[{"role": "user", "content": "Hello, world"}],"model": "claude-sonnet-4-20250514"}
            "content_digest": "sha-256=:TBejC824Zkyj+msrl4D0xulzq7c91UhOJBeERaWGnd0=:",
        }
    )
    signing_key = SigningKey(
        provider_id="signingkey_1234abcd",
        kms_key_arn="arn:aws:kms:eu-west-2:000000000000:alias/test-key",
    )

    signature_params, signature_base = _build_signature_params_and_base(
        req, signing_key, api_key, created, algorithm
    )

    assert (
        signature_params
        == '("@method" "@target-uri" "content-digest" "content-type" "x-api-key");created=1758628645;keyid="signingkey_1234abcd";alg="ecdsa-p256-sha256"'
    )
    assert signature_base == (
        b'"@method": POST\n'
        b'"@target-uri": https://api.anthropic.com/v1/messages\n'
        b'"content-digest": sha-256=:TBejC824Zkyj+msrl4D0xulzq7c91UhOJBeERaWGnd0=:\n'
        b'"content-type": application/json\n'
        b'"x-api-key": token123\n'
        b'"@signature-params": ("@method" "@target-uri" "content-digest" "content-type" "x-api-key")'
        b';created=1758628645;keyid="signingkey_1234abcd";alg="ecdsa-p256-sha256"'
    )


@pytest.fixture()
def anthropic_test_cases() -> list[dict[str, Any]]:
    """Load Anthropic signing test cases from JSON file."""
    test_file = (
        Path(__file__).parent.parent.parent
        / "data"
        / "anthropic_signing_test_cases.json"
    )
    with open(test_file) as f:
        data = json.load(f)
    return data["test_vectors"]


def _sign_with_private_key(private_key_pem: str, message_digest: bytes) -> bytes:
    """Sign a pre-hashed message digest using RFC 6979 deterministic ECDSA P-256 SHA-256.

    This matches AWS KMS behavior when MessageType="DIGEST" is used.
    """
    private_key = cast(
        ec.EllipticCurvePrivateKey,
        serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
        ),
    )
    return private_key.sign(
        message_digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True),
    )


def _verify_signature(
    public_key_pem: str, message_digest: bytes, signature: bytes
) -> bool:
    """Verify an ECDSA signature against a pre-hashed message digest."""
    public_key = cast(
        ec.EllipticCurvePublicKey,
        serialization.load_pem_public_key(public_key_pem.encode()),
    )

    try:
        public_key.verify(
            signature,
            message_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True),
        )
        return True
    except Exception:
        return False


@patch("portunus.services.signing_service.boto3.client")
def test_sign_request_with_anthropic_test_cases(
    mock_boto3_client: MagicMock,
    anthropic_test_cases: list[dict[str, Any]],
) -> None:
    """Test sign_request using official Anthropic test cases with mocked KMS."""
    # Only test ECDSA case (deterministic), skip RSA-PSS (non-deterministic)
    ecdsa_test_case = next(
        tc for tc in anthropic_test_cases if tc["algorithm"] == "ecdsa-p256-sha256"
    )

    test_keys = ecdsa_test_case["keys"]
    test_request = ecdsa_test_case["request"]
    test_sig_params = ecdsa_test_case["signature_params"]
    expected = ecdsa_test_case["expected_values"]
    http_headers = ecdsa_test_case["http_headers"]

    signable_request = SignableRequest(
        type="anthropic",
        url=test_request["target_uri"],
        method=test_request["method"],
        content_type=test_request["content_type"],
        content_digest=expected["content_digest"],
    )

    signing_key = SigningKey(
        provider_id=test_sig_params["keyid"],
        # any KMS key ARN will do since we're mocking KMS
        kms_key_arn="arn:aws:kms:us-east-1:000000000000:key/test",
    )
    api_key = http_headers["X-API-Key"]

    # Sign locally with the test private key to mock KMS response
    with freeze_time(
        datetime.fromtimestamp(test_sig_params["created"], tz=timezone.utc)
    ):
        signature_params, signature_base = _build_signature_params_and_base(
            signable_request,
            signing_key,
            api_key,
            test_sig_params["created"],
            test_sig_params["alg"],
        )

        # Expected format: "sig1=<params>"
        expected_params = expected["signature_input"].removeprefix("sig1=")
        assert signature_params == expected_params

        assert f"created={test_sig_params['created']}" in signature_params
        assert f'keyid="{test_sig_params["keyid"]}"' in signature_params
        assert f'alg="{test_sig_params["alg"]}"' in signature_params

        # Verify signing string matches expected
        assert signature_base.decode("ascii") == expected["signing_string"]

        message_digest = hashlib.sha256(signature_base).digest()
        local_signature = _sign_with_private_key(
            test_keys["private_key_pem"], message_digest
        )

        # Mock KMS client to return our local signature
        mock_kms = MagicMock()
        mock_kms.sign.return_value = {"Signature": local_signature}
        mock_boto3_client.return_value = mock_kms

        # Create mock user credentials
        user_credentials = AwsCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="FakeSessionToken123",
        )

        headers = sign_request(signable_request, signing_key, api_key, user_credentials)

    # Verify deterministic signing: sign again with the same key and verify it
    # produces the same signature
    local_signature2 = _sign_with_private_key(
        test_keys["private_key_pem"], message_digest
    )
    assert (
        local_signature == local_signature2
    ), "RFC 6979 deterministic ECDSA should produce identical signatures"

    # Verify signature headers match expected from test vector
    assert headers["Signature-Input"] == expected["signature_input"]
    assert headers["Signature"] == expected["signature"]

    # Signature header format: `sig1=:{base64}:`
    signature_match = re.match(r"^sig1=:(.+):$", headers["Signature"])
    assert (
        signature_match is not None
    ), f"Signature header format invalid: {headers['Signature']}"
    signature_b64 = signature_match.group(1)
    signature_bytes = base64.b64decode(signature_b64)

    # Verify the signature is cryptographically valid with the test case's public key
    assert _verify_signature(
        test_keys["public_key_pem"], message_digest, signature_bytes
    ), "Generated signature failed verification with public key"

    # Verify KMS was called correctly
    mock_kms.sign.assert_called_once_with(
        KeyId=signing_key.kms_key_arn,
        Message=message_digest,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )
