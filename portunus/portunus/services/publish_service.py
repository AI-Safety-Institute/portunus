"""Publish service: ships audit records to Kinesis Firehose direct-PUT.

``build_*`` methods serialize records to bytes; :meth:`put_record_batch` ships
them via Firehose ``PutRecordBatch``. The bounded publish queue (see
:mod:`publish_queue`) drives batching, so memory stays bounded by the queue cap.
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
from portunus.services.xray_service import capture_async
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")

# A built record: target delivery stream + newline-terminated JSON bytes.
BuiltRecord = Tuple[str, bytes]

# Firehose PutRecordBatch hard limits: 500 records and 4 MiB per call.
_MAX_BATCH_RECORDS = 500
_MAX_BATCH_BYTES = 4 * 1024 * 1024


def _serialize(record_data: Dict[str, Any]) -> bytes:
    """Serialize a record dict to newline-terminated JSON bytes."""
    return orjson.dumps(record_data, default=str) + b"\n"


def _chunk_records(records: List[bytes]) -> List[List[bytes]]:
    """Split records into Firehose-legal batches (<=500 recs, <=4 MiB).

    A record over 4 MiB gets its own chunk and is rejected by Firehose
    (counted failed) rather than dropped silently here; body records are
    already capped well under this by ``FIREHOSE_MAX_RECORD_SIZE``.
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

        Splits into legal chunks (<=500 / <=4 MiB). On partial failure the
        failed subset (via ``RequestResponses[].ErrorCode``) is retried once —
        audit is fire-and-forget with no other retry. Survivors are logged with
        their error codes (payload-free) so loss is observable. Returns the
        count Firehose did NOT accept. Never raises.
        """
        if not stream_name or not records:
            return 0

        client = await self.state_service.get_firehose_client()
        failed = 0
        for chunk in _chunk_records(records):
            failed += await self._put_chunk_with_retry(client, stream_name, chunk)
        return failed

    async def _put_chunk_with_retry(
        self, client: Any, stream_name: str, chunk: List[bytes]
    ) -> int:
        """PutRecordBatch one legal-sized chunk; retry the failed subset once.

        Returns the number of records not accepted after the retry.
        """
        records = chunk
        last_error_codes: Dict[str, int] = {}
        for attempt in (1, 2):
            try:
                resp = await client.put_record_batch(
                    DeliveryStreamName=stream_name,
                    Records=[{"Data": data} for data in records],
                )
            except Exception as e:
                # Log type(e).__name__ only — botocore messages can carry
                # payload fragments (customer body content).
                logger.error(
                    "put_record_batch on %s raised: %s (%d records, attempt %d)",
                    stream_name,
                    type(e).__name__,
                    len(records),
                    attempt,
                )
                return len(records)

            failed_count = int(resp.get("FailedPutCount", 0) or 0)
            if failed_count == 0:
                return 0

            # Identify the failed records by position so we retry only those.
            responses = resp.get("RequestResponses", [])
            retry: List[bytes] = []
            last_error_codes = {}
            for data, r in zip(records, responses):
                code = r.get("ErrorCode")
                if code:
                    retry.append(data)
                    last_error_codes[code] = last_error_codes.get(code, 0) + 1
            # Fallback for missing/misaligned responses: treat the tail as
            # failed so we never silently under-count.
            if not retry:
                retry = records[len(records) - failed_count :]

            if attempt == 1:
                logger.warning(
                    "put_record_batch on %s: %d/%d failed (%s); retrying subset",
                    stream_name,
                    len(retry),
                    len(records),
                    last_error_codes,
                )
                records = retry
                continue

            # Second attempt still failed — give up; surface the loss.
            logger.error(
                "put_record_batch on %s: %d records unrecoverable after retry (%s)",
                stream_name,
                len(retry),
                last_error_codes,
            )
            return len(retry)
        return 0

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
        final_chunk: bool = False,
        frame_index: Optional[int] = None,
    ) -> Optional[BuiltRecord]:
        """Build one request-body chunk record.

        ``dropped=True``: sentinel for a chunk the queue couldn't accept
        (``body_bytes`` empty). ``truncated=True``: payload capped (WS deflate
        path only). ``final_chunk=True``: terminal chunk of a streamed
        (``num_chunks=0``) body, emitted with Envoy ``end_of_stream``, so the
        ETL can detect a lost trailing chunk. ``frame_index``: per-direction WS
        frame ordinal (None for HTTP); Glue keys WS frames by (request_id,
        frame_index).
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
            final_chunk=final_chunk,
            frame_index=frame_index,
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
        final_chunk: bool = False,
        frame_index: Optional[int] = None,
    ) -> Optional[BuiltRecord]:
        """Build one response-body chunk record.

        ``dropped`` / ``truncated`` / ``final_chunk`` / ``frame_index``
        semantics mirror :meth:`build_request_body`.
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
            final_chunk=final_chunk,
            frame_index=frame_index,
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
