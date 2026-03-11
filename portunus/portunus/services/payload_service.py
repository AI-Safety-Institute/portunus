"""
Payload handling service module.

This module contains functions for working with API proxy payloads, including
encoding, decoding, and overriding API keys with AWS Secrets Manager references.
"""

import json
from base64 import b64decode, b64encode


def encode_payload(credentials: dict, secret_arn: str) -> str:
    """Encode credentials and secret ARN into a base64 payload for the API key proxy.

    This is the inverse of ``decode_payload``.

    Args:
        credentials: Dictionary with AWS credential keys (AccessKeyId,
            SecretAccessKey, SessionToken, and optionally Expiration).
        secret_arn: The ARN of the secret to retrieve.

    Returns:
        Base64-encoded JSON string suitable for the Authorization header.
    """
    payload_dict = {
        "credentials": {
            "access_key_id": credentials["AccessKeyId"],
            "secret_access_key": credentials["SecretAccessKey"],
            "session_token": credentials["SessionToken"],
        },
        "expiration": credentials["Expiration"],
        "secret_arn": secret_arn,
    }
    json_bytes = json.dumps(payload_dict, default=str).encode("utf-8")
    return b64encode(json_bytes).decode("utf-8")


def decode_payload(payload: str) -> dict:
    """Decode a base64-encoded payload from the API key proxy.

    The returned dictionary contains the credentials and secret ARN. This is the
    inverse of ``encode_payload``.

    Args:
        payload (str): The base64-encoded payload to decode

    Returns:
        dict: Dictionary containing "credentials" and "secret_arn" fields

    Raises:
        json.JSONDecodeError: If the payload is not valid JSON after decoding
        UnicodeDecodeError: If the payload cannot be decoded as UTF-8
    """
    return json.loads(b64decode(payload).decode("utf-8"))
