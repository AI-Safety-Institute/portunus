"""Every non-metadata Kinesis record carries the caller's project.

Firehose partitions each stream by ``.project``, so each record type must
serialise it and declare it in the Glue schema the infra builds tables from.
"""

import pytest

from portunus.models import (
    RequestBodyRecord,
    RequestHeadersRecord,
    RequestTrailersRecord,
    ResponseBodyRecord,
    ResponseHeadersRecord,
    ResponseTrailersRecord,
    WSSummaryRecord,
)

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
    if record_cls is WSSummaryRecord:
        return record_cls(
            request_id="r",
            timestamp=TS,
            published_at=PUB,
            duration_seconds=1.0,
            **extra,
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
    WSSummaryRecord,
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
