"""Tests for the payload service functions."""

import base64
import json

import pytest

from portunus.exceptions import PayloadError
from portunus.models import AuthPayload
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


def test_undecodable_payload_is_not_echoed_in_the_error():
    """The payload holds credentials, so a decode error must not repeat it."""
    raw = base64.b64encode(b'{"credentials": {"session_token": "tok-SECRET"').decode()

    with pytest.raises(PayloadError) as exc_info:
        AuthPayload.from_contents(raw)

    message = str(exc_info.value)
    assert message.startswith("Failed to decode authorization payload: ")
    assert raw not in message
    assert "tok-SECRET" not in message
    assert isinstance(exc_info.value.__cause__, json.JSONDecodeError)


def _encoded(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


def test_credential_expiry_is_read_from_the_payload_top_level():
    """``encode_payload`` writes ``expiration`` beside ``credentials``."""
    payload = encode_payload(
        {
            "AccessKeyId": "AKIATEST",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
            "Expiration": "2030-01-01T00:00:00+00:00",
        },
        "arn:aws:secretsmanager:eu-west-2:123456789012:secret:key",
    )

    parsed = AuthPayload.from_contents(payload)

    assert parsed.credentials.expiration is not None
    assert parsed.credentials.expiration.isoformat() == "2030-01-01T00:00:00+00:00"
    assert parsed.credentials.seconds_until_expiration() is not None


def test_expiry_inside_credentials_takes_precedence():
    parsed = AuthPayload.from_contents(
        _encoded(
            {
                "credentials": {
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "SECRET",
                    "expiration": "2031-01-01T00:00:00+00:00",
                },
                "expiration": "2030-01-01T00:00:00+00:00",
                "secret_arn": "arn",
            }
        )
    )

    assert parsed.credentials.expiration is not None
    assert parsed.credentials.expiration.year == 2031


def test_payload_without_any_expiry_has_none():
    parsed = AuthPayload.from_contents(
        _encoded(
            {
                "credentials": {"access_key_id": "AKIATEST", "secret_access_key": "S"},
                "secret_arn": "arn",
            }
        )
    )

    assert parsed.credentials.expiration is None
    assert parsed.credentials.seconds_until_expiration() is None
