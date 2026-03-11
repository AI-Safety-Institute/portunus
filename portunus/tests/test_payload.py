"""Tests for the payload service functions."""

from portunus.services.payload_service import (
    decode_payload,
    encode_payload,
)


def test_decode_payload():
    """Test construction and decoding of API proxy payload."""
    credentials = {
        "AccessKeyId": "blah1",
        "SecretAccessKey": "blah2",
        "SessionToken": "blah3",
        "Expiration": "blah4",
    }
    secret_arn = "blah5"

    payload = encode_payload(credentials, secret_arn)

    decoded_payload = decode_payload(payload)

    assert decoded_payload["credentials"]["access_key_id"] == "blah1"
    assert decoded_payload["credentials"]["secret_access_key"] == "blah2"
    assert decoded_payload["credentials"]["session_token"] == "blah3"
    assert decoded_payload["expiration"] == "blah4"
    assert decoded_payload["secret_arn"] == "blah5"
