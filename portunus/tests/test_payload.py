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
