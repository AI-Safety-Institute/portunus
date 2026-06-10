"""Publish service: ships audit records to Kinesis Firehose direct-PUT."""

import base64
import logging
from typing import Any, Dict, Optional

import orjson

from portunus.config import config
from portunus.exceptions import ServiceError
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


class PublishService:
    """Service for publishing audit records to Kinesis Firehose direct-PUT."""

    def __init__(self, state_service: Optional[StateService] = None):
        """Initialize the PublishService."""
        self.state_service = state_service or StateService()

    async def publish_to_firehose(
        self,
        stream_name: str,
        record_data: Dict[str, Any],
        partition_key: str,
    ) -> bool:
        """Fire-and-forget single ``PutRecord`` on a Firehose delivery stream.

        ``partition_key`` is unused by Firehose (no shards) but kept for
        log correlation with the caller's request_id.
        """
        if not stream_name:
            return False

        client = await self.state_service.get_firehose_client()
        try:
            data_bytes = orjson.dumps(record_data, default=str) + b"\n"
            await client.put_record(
                DeliveryStreamName=stream_name,
                Record={"Data": data_bytes},
            )
            return True
        except Exception as e:
            # Log type(e).__name__ only — botocore exceptions can carry
            # payload fragments (customer body content) in their messages.
            logger.error(
                "put_record on %s failed: %s",
                stream_name,
                type(e).__name__,
            )
            raise ServiceError(f"Failed to publish to Firehose: {type(e).__name__}")

    async def publish_metadata(
        self,
        request_id: str,
        timestamp: str,
        principal_info: Dict[str, Any],
        secret_arn: Optional[str] = None,
    ) -> bool:
        """Publish the per-request principal/secret metadata record."""
        if not config.firehose.metadata_stream_name:
            logger.warning("Metadata stream not configured, skipping publish")
            return False

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

        return await self.publish_to_firehose(
            config.firehose.metadata_stream_name, record.to_dict(), request_id
        )

    async def publish_request_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish a request-headers record."""
        if not config.firehose.request_headers_stream_name:
            logger.warning("Request headers stream not configured, skipping publish")
            return False

        record = RequestHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self.publish_to_firehose(
            config.firehose.request_headers_stream_name, record.to_dict(), request_id
        )

    async def publish_request_body(
        self,
        request_id: str,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        num_chunks: int,
        *,
        dropped: bool = False,
        truncated: bool = False,
    ) -> bool:
        """Publish one request-body chunk record.

        ``dropped=True`` is a sentinel marker emitted in place of a chunk
        the publish queue could not accept; ``body_bytes`` is empty in
        that case. ``truncated=True`` marks a chunk whose payload was
        capped (currently only the WS deflate path).
        """
        if not config.firehose.request_body_stream_name:
            logger.warning("Request body stream not configured, skipping publish")
            return False

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

        return await self.publish_to_firehose(
            config.firehose.request_body_stream_name, record.to_dict(), request_id
        )

    async def publish_request_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish a request-trailers record."""
        if not config.firehose.request_trailers_stream_name:
            logger.warning("Request trailers stream not configured, skipping publish")
            return False

        record = RequestTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self.publish_to_firehose(
            config.firehose.request_trailers_stream_name, record.to_dict(), request_id
        )

    async def publish_response_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish a response-headers record."""
        if not config.firehose.response_headers_stream_name:
            logger.warning("Response headers stream not configured, skipping publish")
            return False

        record = ResponseHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self.publish_to_firehose(
            config.firehose.response_headers_stream_name, record.to_dict(), request_id
        )

    async def publish_response_body(
        self,
        request_id: str,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        num_chunks: int,
        *,
        dropped: bool = False,
        truncated: bool = False,
    ) -> bool:
        """Publish one response-body chunk record.

        ``dropped`` / ``truncated`` semantics mirror
        :meth:`publish_request_body`.
        """
        if not config.firehose.response_body_stream_name:
            logger.warning("Response body stream not configured, skipping publish")
            return False

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

        return await self.publish_to_firehose(
            config.firehose.response_body_stream_name, record.to_dict(), request_id
        )

    async def publish_response_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish a response-trailers record."""
        if not config.firehose.response_trailers_stream_name:
            logger.warning("Response trailers stream not configured, skipping publish")
            return False

        record = ResponseTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self.publish_to_firehose(
            config.firehose.response_trailers_stream_name, record.to_dict(), request_id
        )

    async def publish_ws_summary(
        self,
        record: WSSummaryRecord,
    ) -> bool:
        """Publish a per-connection WebSocket summary record."""
        if not config.firehose.ws_summary_stream_name:
            logger.warning("WS summary stream not configured, skipping publish")
            return False

        return await self.publish_to_firehose(
            config.firehose.ws_summary_stream_name,
            record.to_dict(),
            record.request_id,
        )
