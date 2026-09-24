"""Publish service: ships audit records to Kinesis Data Streams.

``build_*`` methods serialize records to bytes; :meth:`put_record_batch` packs
and ships them via Kinesis ``PutRecords``. Each stream feeds a Firehose that
deaggregates the packs and delivers to S3. The bounded publish queue (see
:mod:`publish_queue`) drives batching, so memory stays bounded by the queue cap.
"""

import asyncio
import base64
import logging
import random
import uuid
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

# A built record: target stream + newline-terminated JSON bytes.
BuiltRecord = Tuple[str, bytes]

# Kinesis PutRecords hard limits: 500 records and 5 MiB per call, 1 MiB per
# record (data + partition key).
_MAX_CALL_RECORDS = 500
_MAX_CALL_BYTES = 5 * 1024 * 1024

# Audit records are packed, newline-delimited, into shared KDS records; the
# Firehose reading each stream splits them again with RecordDeAggregation
# (JSON sub-records, at most 500 per KDS record) before dynamic partitioning.
# 256 KiB rather than the 1 MiB maximum so one record can't use up a whole
# shard-second (1 MiB/s per shard) under random placement.
_PACK_TARGET_BYTES = 256 * 1024
_PACK_MAX_RECORDS = 500

# A random partition key per packed record. A pack mixes many requests, so a
# request- or connection-scoped key would mean nothing; random keys spread
# every busy WebSocket or streamed body across all shards instead of pinning
# it to one (on-demand scaling can't split a hot key). Consumers reassemble by
# request_id + chunk_id / frame_index, so KDS ordering isn't needed.
_PARTITION_KEY_BYTES = 32

# Per-record ErrorCodes that mean "the stream is over its quota", as opposed
# to a malformed record. Counted separately so an under-provisioned stream is
# distinguishable from a code bug in the CloudWatch metrics.
_THROTTLE_ERROR_CODES = frozenset(
    {
        "ServiceUnavailableException",
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
    }
)


# A packed KDS record: data + the number of audit records it carries.
Pack = Tuple[bytes, int]


def _serialize(record_data: Dict[str, Any]) -> bytes:
    """Serialize a record dict to newline-terminated JSON bytes."""
    return orjson.dumps(record_data, default=str, option=orjson.OPT_APPEND_NEWLINE)


def _partition_key() -> str:
    return uuid.uuid4().hex


def _pack_records(records: List[bytes]) -> List[Pack]:
    """Concatenate newline-terminated records into <=256 KiB / <=500 packs.

    A record over the target gets a pack of its own (body records are capped
    under the 1 MiB KDS limit by ``FIREHOSE_MAX_RECORD_SIZE``). A record
    missing its trailing newline gets one: Firehose de-aggregation splits
    packs on newlines, so one bare record would corrupt its whole pack.
    """
    packs: List[Pack] = []
    current: List[bytes] = []
    current_bytes = 0
    for data in records:
        if not data.endswith(b"\n"):
            data += b"\n"
        size = len(data)
        if current and (
            len(current) >= _PACK_MAX_RECORDS
            or current_bytes + size > _PACK_TARGET_BYTES
        ):
            packs.append((b"".join(current), len(current)))
            current = []
            current_bytes = 0
        current.append(data)
        current_bytes += size
    if current:
        packs.append((b"".join(current), len(current)))
    return packs


def _chunk_packs(packs: List[Pack]) -> List[List[Pack]]:
    """Split packs into PutRecords-legal calls (<=500 records, <=5 MiB)."""
    chunks: List[List[Pack]] = []
    current: List[Pack] = []
    current_bytes = 0
    for pack in packs:
        size = len(pack[0]) + _PARTITION_KEY_BYTES
        if current and (
            len(current) >= _MAX_CALL_RECORDS or current_bytes + size > _MAX_CALL_BYTES
        ):
            chunks.append(current)
            current = []
            current_bytes = 0
        current.append(pack)
        current_bytes += size
    if current:
        chunks.append(current)
    return chunks


class PublishService:
    """Builds audit records and ships them to Kinesis Data Streams."""

    def __init__(self, state_service: Optional[StateService] = None):
        """Initialize the PublishService."""
        self.state_service = state_service or StateService()
        # Cumulative failure counters, in audit records, surfaced as
        # per-interval deltas by the metrics reporter. Throttles are separated
        # from hard errors because they mean "raise the stream's capacity",
        # not "fix a bug"; both already log, but a log line is not an alarm.
        self.throttled_total = 0
        self.put_errors_total = 0

    async def put_record_batch(self, stream_name: str, records: List[bytes]) -> int:
        """Ship ``records`` to the ``stream_name`` data stream via ``PutRecords``.

        Packs records into shared KDS records, then splits those into legal
        calls. On partial failure the failed packs (via
        ``Records[].ErrorCode``) are retried once, under fresh partition keys,
        after a short jittered backoff — audit is fire-and-forget with no
        other retry. Survivors are logged with their error codes
        (payload-free) so loss is observable. Returns the count of audit
        records Kinesis did NOT accept. Never raises.
        """
        if not stream_name or not records:
            return 0

        client = await self.state_service.get_kinesis_client()
        failed = 0
        for chunk in _chunk_packs(_pack_records(records)):
            failed += await self._put_chunk_with_retry(client, stream_name, chunk)
        return failed

    async def _put_chunk_with_retry(
        self, client: Any, stream_name: str, chunk: List[Pack]
    ) -> int:
        """PutRecords one legal-sized chunk; retry the failed packs once.

        Returns the number of audit records not accepted after the retry.
        """
        packs = chunk
        last_error_codes: Dict[str, int] = {}
        for attempt in (1, 2):
            pending = sum(n for _, n in packs)
            try:
                resp = await client.put_records(
                    StreamName=stream_name,
                    Records=[
                        {"Data": data, "PartitionKey": _partition_key()}
                        for data, _ in packs
                    ],
                )
            except Exception as e:
                self.put_errors_total += pending
                # Log type(e).__name__ only — botocore messages can carry
                # payload fragments (customer body content).
                logger.error(
                    "put_records on %s raised: %s (%d records, attempt %d)",
                    stream_name,
                    type(e).__name__,
                    pending,
                    attempt,
                )
                return pending

            failed_count = resp.get("FailedRecordCount")
            responses = resp.get("Records")
            consistent = (
                type(failed_count) is int
                and isinstance(responses, list)
                and len(responses) == len(packs)
                and all(
                    isinstance(r, dict)
                    and bool(r.get("SequenceNumber")) != bool(r.get("ErrorCode"))
                    for r in responses
                )
                and sum(bool(r.get("ErrorCode")) for r in responses) == failed_count
            )
            retry: List[Pack] = []
            last_error_codes = {}
            if consistent:
                for pack, r in zip(packs, responses):
                    code = r.get("ErrorCode")
                    if code:
                        retry.append(pack)
                        last_error_codes[code] = last_error_codes.get(code, 0) + 1
                        if code in _THROTTLE_ERROR_CODES:
                            self.throttled_total += pack[1]
            else:
                # A misaligned response cannot confirm which inputs succeeded.
                # Retrying the whole group may duplicate records, but never hides loss.
                retry = packs
                logger.warning(
                    "Inconsistent Kinesis response on %s; %d records unconfirmed",
                    stream_name,
                    pending,
                )
            if not retry:
                return 0

            retry_count = sum(n for _, n in retry)
            if attempt == 1:
                logger.warning(
                    "put_records on %s: %d/%d records failed (%s); "
                    "retrying subset after backoff",
                    stream_name,
                    retry_count,
                    pending,
                    last_error_codes,
                )
                packs = retry
                # Per-record rejection arrives inside HTTP 200, so SDK
                # request-level retry backoff does not cover it.
                await asyncio.sleep(random.uniform(0.5, 1.5))
                continue

            # Second attempt still failed — give up; surface the loss.
            logger.error(
                "put_records on %s: %d records unrecoverable after retry (%s)",
                stream_name,
                retry_count,
                last_error_codes,
            )
            return retry_count
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
        (``body_bytes`` empty). ``truncated=True``: capture is incomplete
        or capped. ``final_chunk=True``: terminal chunk of a streamed
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
