"""The six non-metadata Kinesis records carry the caller's project.

Firehose partitions every stream by ``.project``, so each record type must
serialise it and declare it in the Glue schema the infra builds tables from.
"""

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from portunus.config import config
from portunus.models import (
    RequestBodyRecord,
    RequestHeadersRecord,
    RequestTrailersRecord,
    ResponseBodyRecord,
    ResponseHeadersRecord,
    ResponseTrailersRecord,
)
from portunus.services.publish_service import PublishService

TS = "2025-01-01T00:00:00Z"
PUB = "2025-01-01T00:00:01Z"


def _build(record_cls, **extra):
    if record_cls in (RequestHeadersRecord, ResponseHeadersRecord):
        return record_cls(
            request_id="r", raw_headers={}, timestamp=TS, published_at=PUB, **extra
        )
    if record_cls in (RequestTrailersRecord, ResponseTrailersRecord):
        return record_cls(
            request_id="r", trailers={}, timestamp=TS, published_at=PUB, **extra
        )
    return record_cls(
        request_id="r",
        body="",
        body_size=0,
        timestamp=TS,
        chunk_id=0,
        num_chunks=1,
        published_at=PUB,
        **extra,
    )


RECORD_CLASSES = [
    RequestHeadersRecord,
    RequestBodyRecord,
    RequestTrailersRecord,
    ResponseHeadersRecord,
    ResponseBodyRecord,
    ResponseTrailersRecord,
]


@pytest.mark.parametrize("record_cls", RECORD_CLASSES)
def test_project_defaults_to_none_and_serialises(record_cls):
    """Records built without a project still emit the key, as null."""
    assert _build(record_cls).to_dict()["project"] is None
    assert _build(record_cls, project="alpha").to_dict()["project"] == "alpha"


@pytest.mark.parametrize("record_cls", RECORD_CLASSES)
def test_project_is_the_last_glue_column(record_cls):
    """Appending keeps existing column positions stable for the deployed tables."""
    assert record_cls.glue_schema()[-1] == {"name": "project", "type": "string"}
    assert "project" in {col["name"] for col in record_cls.glue_schema()}


_HEADERS: dict[str, Any] = {"headers": {}}
_TRAILERS: dict[str, Any] = {"trailers": {}}
_BODY: dict[str, Any] = {"body_bytes": b"x", "chunk_id": 0, "num_chunks": 1}

# (publish method, its stream-name field on config.kinesis, its extra kwargs)
PUBLISH_METHODS = [
    ("publish_request_headers", "request_headers_stream_name", _HEADERS),
    ("publish_request_body", "request_body_stream_name", _BODY),
    ("publish_request_trailers", "request_trailers_stream_name", _TRAILERS),
    ("publish_response_headers", "response_headers_stream_name", _HEADERS),
    ("publish_response_body", "response_body_stream_name", _BODY),
    ("publish_response_trailers", "response_trailers_stream_name", _TRAILERS),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "stream_field", "kwargs"), PUBLISH_METHODS)
async def test_publish_builder_puts_project_on_the_kinesis_record(
    monkeypatch, method, stream_field, kwargs
):
    """Each publish_* method carries project= into the bytes sent to Kinesis."""
    monkeypatch.setattr(config.kinesis, stream_field, "test-stream")
    monkeypatch.setattr(config.aws, "endpoint_url", None)
    kinesis_client = MagicMock()
    kinesis_client.put_record = AsyncMock(
        return_value={"ShardId": "shardId-0", "SequenceNumber": "12345678"}
    )
    state_service = MagicMock()
    state_service.get_kinesis_client = AsyncMock(return_value=kinesis_client)
    publish_service = PublishService(state_service=state_service)

    ok = await getattr(publish_service, method)(
        request_id="r", timestamp=TS, project="alpha", **kwargs
    )

    assert ok is True
    sent = kinesis_client.put_record.await_args.kwargs
    assert sent["StreamName"] == "test-stream"
    assert json.loads(sent["Data"])["project"] == "alpha"
