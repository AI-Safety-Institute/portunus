"""Publish service: ships audit records to Kinesis Firehose direct-PUT.

Records are *built* (synchronously serialized to bytes) by the ``build_*``
methods and shipped in batches by :meth:`put_record_batch` via Firehose
``PutRecordBatch``. The bounded publish queue (see :mod:`publish_queue`) drains
itself in stream-grouped chunks and calls ``put_record_batch`` — so batching is
opportunistic (only what's already queued), keeping memory bounded by the queue
cap while cutting records/s ~Nx vs one ``put_record`` per event.
"""

import base64
import logging
from typing import Any, Dict, List, Optional, Tuple

import orjson

from portunus.config import config
from portunus.models import (
    MetadataRecord,
    RequestBodyRecord,
    RequestHeadersRecord,
    RequestTrailersRecord,
    ResponseBodyRecord,
    ResponseHeadersRecord,
    ResponseTrailersRecord,
    WSSummaryRecord,
)
from portunus.services.state_service import StateService
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")

# A built record ready for Firehose: the target delivery stream and the
# newline-terminated JSON bytes.
BuiltRecord = Tuple[str, bytes]

# Firehose PutRecordBatch hard limits: 500 records and 4 MiB per call.
_MAX_BATCH_RECORDS = 500
_MAX_BATCH_BYTES = 4 * 1024 * 1024


def _serialize(record_data: Dict[str, Any]) -> bytes:
    """Serialize a record dict to newline-terminated JSON bytes."""
    return orjson.dumps(record_data, default=str) + b"\n"


def _chunk_records(records: List[bytes]) -> List[List[bytes]]:
    """Split records into Firehose-legal batches (<=500 recs, <=4 MiB).

    A single record over 4 MiB can't fit a batch; it's placed in its own
    chunk and will be rejected by Firehose (counted as failed) rather than
    silently dropped here — body records are already capped well under this
    by ``FIREHOSE_MAX_RECORD_SIZE``.
    """
    chunks: List[List[bytes]] = []
    current: List[bytes] = []
    current_bytes = 0
    for data in records:
        size = len(data)
        if current and (
            len(current) >= _MAX_BATCH_RECORDS
            or current_bytes + size > _MAX_BATCH_BYTES
        ):
            chunks.append(current)
            current = []
            current_bytes = 0
        current.append(data)
        current_bytes += size
    if current:
        chunks.append(current)
    return chunks


class PublishService:
    """Builds audit records and ships them to Firehose via PutRecordBatch."""

    def __init__(self, state_service: Optional[StateService] = None):
        """Initialize the PublishService."""
        self.state_service = state_service or StateService()

    async def put_record_batch(self, stream_name: str, records: List[bytes]) -> int:
        """Ship ``records`` to ``stream_name`` via Firehose ``PutRecordBatch``.

        Splits into Firehose-legal chunks (<=500 records / <=4 MiB) and
        retries nothing — audit is fire-and-forget under
        ``observability_mode``. Returns the number of records Firehose did
        NOT accept (transport error or per-record ``PutRecordBatch`` failure),
        so the caller can surface delivery loss. Never raises.
        """
        if not stream_name or not records:
            return 0

        client = await self.state_service.get_firehose_client()
        failed = 0
        for chunk in _chunk_records(records):
            try:
                resp = await client.put_record_batch(
                    DeliveryStreamName=stream_name,
                    Records=[{"Data": data} for data in chunk],
                )
                # PutRecordBatch is partial-success: FailedPutCount records
                # were rejected (throttling etc.) while others landed.
                failed += int(resp.get("FailedPutCount", 0) or 0)
            except Exception as e:
                # Log type(e).__name__ only — botocore exceptions can carry
                # payload fragments (customer body content) in their messages.
                logger.error(
                    "put_record_batch on %s failed: %s (%d records)",
                    stream_name,
                    type(e).__name__,
                    len(chunk),
                )
                failed += len(chunk)
        return failed

    def build_metadata(
        self,
        request_id: str,
        timestamp: str,
        principal_info: Dict[str, Any],
        secret_arn: Optional[str] = None,
    ) -> Optional[BuiltRecord]:
        """Build the per-request principal/secret metadata record."""
        if not config.firehose.metadata_stream_name:
            logger.warning("Metadata stream not configured, skipping publish")
            return None

        record = MetadataRecord(
            request_id=request_id,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
            account_id=principal_info.get("account_id"),
            principal=principal_info.get("principal"),
            principal_arn=principal_info.get("arn"),
            project=principal_info.get("project"),
            session_name=principal_info.get("session_name"),
            secret_arn=secret_arn,
        )
        return config.firehose.metadata_stream_name, _serialize(record.to_dict())

    def build_request_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> Optional[BuiltRecord]:
        """Build a request-headers record."""
        if not config.firehose.request_headers_stream_name:
            logger.warning("Request headers stream not configured, skipping publish")
            return None

        record = RequestHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )
        return config.firehose.request_headers_stream_name, _serialize(record.to_dict())

    def build_request_body(
        self,
        request_id: str,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        num_chunks: int,
        *,
        dropped: bool = False,
        truncated: bool = False,
    ) -> Optional[BuiltRecord]:
        """Build one request-body chunk record.

        ``dropped=True`` is a sentinel marker emitted in place of a chunk
        the publish queue could not accept; ``body_bytes`` is empty in
        that case. ``truncated=True`` marks a chunk whose payload was
        capped (currently only the WS deflate path).
        """
        if not config.firehose.request_body_stream_name:
            logger.warning("Request body stream not configured, skipping publish")
            return None

        body_b64 = base64.b64encode(body_bytes).decode("ascii")
        record = RequestBodyRecord(
            request_id=request_id,
            body=body_b64,
            body_size=len(body_bytes),
            timestamp=timestamp,
            chunk_id=chunk_id,
            num_chunks=num_chunks,
            published_at=generate_iso_timestamp(),
            dropped=dropped,
            truncated=truncated,
        )
        return config.firehose.request_body_stream_name, _serialize(record.to_dict())

    def build_request_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> Optional[BuiltRecord]:
        """Build a request-trailers record."""
        if not config.firehose.request_trailers_stream_name:
            logger.warning("Request trailers stream not configured, skipping publish")
            return None

        record = RequestTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )
        return config.firehose.request_trailers_stream_name, _serialize(
            record.to_dict()
        )

    def build_response_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> Optional[BuiltRecord]:
        """Build a response-headers record."""
        if not config.firehose.response_headers_stream_name:
            logger.warning("Response headers stream not configured, skipping publish")
            return None

        record = ResponseHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )
        return config.firehose.response_headers_stream_name, _serialize(
            record.to_dict()
        )

    def build_response_body(
        self,
        request_id: str,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        num_chunks: int,
        *,
        dropped: bool = False,
        truncated: bool = False,
    ) -> Optional[BuiltRecord]:
        """Build one response-body chunk record.

        ``dropped`` / ``truncated`` semantics mirror
        :meth:`build_request_body`.
        """
        if not config.firehose.response_body_stream_name:
            logger.warning("Response body stream not configured, skipping publish")
            return None

        body_b64 = base64.b64encode(body_bytes).decode("ascii")
        record = ResponseBodyRecord(
            request_id=request_id,
            body=body_b64,
            body_size=len(body_bytes),
            timestamp=timestamp,
            chunk_id=chunk_id,
            num_chunks=num_chunks,
            published_at=generate_iso_timestamp(),
            dropped=dropped,
            truncated=truncated,
        )
        return config.firehose.response_body_stream_name, _serialize(record.to_dict())

    def build_response_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> Optional[BuiltRecord]:
        """Build a response-trailers record."""
        if not config.firehose.response_trailers_stream_name:
            logger.warning("Response trailers stream not configured, skipping publish")
            return None

        record = ResponseTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )
        return config.firehose.response_trailers_stream_name, _serialize(
            record.to_dict()
        )

    def build_ws_summary(
        self,
        record: WSSummaryRecord,
    ) -> Optional[BuiltRecord]:
        """Build a per-connection WebSocket summary record."""
        if not config.firehose.ws_summary_stream_name:
            logger.warning("WS summary stream not configured, skipping publish")
            return None

        return config.firehose.ws_summary_stream_name, _serialize(record.to_dict())
