"""A payload that cannot be decoded is never repeated back or logged.

The payload carries the caller's AWS credentials, and the error response
travels back to wherever the request came from.
"""

import base64
import json
import logging
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from portunus.app import portunus
from portunus.relay.auth import authenticate_ws

SECRET_KEY = "wJalrXUtnFEMISECRETMARKER"
SESSION_TOKEN = "FwoGZXIvYXdzSESSIONMARKER"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


_CREDENTIAL_JSON = json.dumps(
    {
        "credentials": {
            "access_key_id": "AKIATEST",
            "secret_access_key": SECRET_KEY,
            "session_token": SESSION_TOKEN,
        },
        "secret_arn": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:k",
    }
).encode()


@dataclass(frozen=True)
class UndecodablePayload:
    """A payload Portunus must reject, and the strings it must not repeat."""

    payload: str
    sensitive: tuple[str, ...]


UNDECODABLE = {
    "not base64": UndecodablePayload(
        "NOTBASE64MARKER!!@@", ("NOTBASE64MARKER", "!!@@")
    ),
    "credential blob with its last characters missing": UndecodablePayload(
        _b64(_CREDENTIAL_JSON)[:-3],
        (_b64(_CREDENTIAL_JSON)[:40], SECRET_KEY, SESSION_TOKEN),
    ),
    "credential JSON cut off mid-string": UndecodablePayload(
        _b64(_CREDENTIAL_JSON[:-20]),
        (_b64(_CREDENTIAL_JSON[:-20])[:40], SECRET_KEY, SESSION_TOKEN),
    ),
    "credential JSON followed by a stray byte": UndecodablePayload(
        _b64(_CREDENTIAL_JSON + b"\xff"),
        (_b64(_CREDENTIAL_JSON)[:40], SECRET_KEY, SESSION_TOKEN),
    ),
    "a JSON string instead of an object": UndecodablePayload(
        _b64(json.dumps(SECRET_KEY).encode()),
        (_b64(json.dumps(SECRET_KEY).encode()), SECRET_KEY),
    ),
    "a JSON list instead of an object": UndecodablePayload(
        _b64(json.dumps([SECRET_KEY, SESSION_TOKEN]).encode()),
        (SECRET_KEY, SESSION_TOKEN),
    ),
    "credentials given as a string": UndecodablePayload(
        _b64(json.dumps({"credentials": SECRET_KEY}).encode()),
        (_b64(json.dumps({"credentials": SECRET_KEY}).encode()), SECRET_KEY),
    ),
    "a secret key with no access key id": UndecodablePayload(
        _b64(json.dumps({"credentials": {"secret_access_key": SECRET_KEY}}).encode()),
        (SECRET_KEY,),
    ),
}

undecodable = pytest.mark.parametrize(
    "case", UNDECODABLE.values(), ids=UNDECODABLE.keys()
)


@pytest.fixture
def mock_xray():
    segment = MagicMock()
    segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as xray:
        xray.recorder.current_segment.return_value = segment
        yield xray


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=portunus), base_url="http://test"
    ) as http_client:
        yield http_client


@undecodable
@pytest.mark.asyncio
async def test_authorise_rejects_without_repeating_the_payload(
    case: UndecodablePayload, client, mock_xray
):
    response = await client.post(
        "/authorise", json={"payload": case.payload, "target_host": "api.example.com"}
    )

    assert response.status_code == 401
    for secret in case.sensitive:
        assert secret not in response.text


@undecodable
@pytest.mark.asyncio
async def test_websocket_rejects_without_logging_or_sending_the_payload(
    case: UndecodablePayload, caplog
):
    websocket = AsyncMock()
    websocket.headers = {"authorization": f"Bearer {case.payload}"}

    with caplog.at_level(logging.DEBUG):
        result = await authenticate_ws(websocket, AsyncMock(), "test-req-id")

    assert result is None
    websocket.close.assert_called_once()
    said = caplog.text + str(websocket.close.call_args)
    for secret in case.sensitive:
        assert secret not in said
