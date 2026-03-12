"""Publish service module.

Constructs log records and delegates transport to a pluggable
StreamPublisher backend.
"""

import base64
import logging
from typing import Any, Dict

from aws_xray_sdk.core import xray_recorder

from portunus.backends.protocols import StreamPublisher
from portunus.config import config
from portunus.models import (
    MetadataRecord,
    RequestBodyRecord,
    RequestHeadersRecord,
    RequestTrailersRecord,
    ResponseBodyRecord,
    ResponseHeadersRecord,
    ResponseTrailersRecord,
)
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")


class PublishService:
    """Constructs log records and publishes via a StreamPublisher backend."""

    def __init__(self, publisher: StreamPublisher):
        self.publisher = publisher

    async def _publish_record(
        self,
        stream_name: str,
        record_data: Dict[str, Any],
        partition_key: str,
    ) -> bool:
        """Publish a record through the configured backend."""
        if not stream_name:
            logger.warning("Stream name not configured, skipping publish")
            return False
        return await self.publisher.publish(stream_name, record_data, partition_key)

    @xray_recorder.capture_async()  # type: ignore
    async def publish_metadata(
        self,
        request_id: str,
        timestamp: str,
        principal_info: Dict[str, Any],
    ) -> bool:
        """Publish metadata to the configured stream."""
        if not config.kinesis.metadata_stream_name:
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
        )

        return await self._publish_record(
            config.kinesis.metadata_stream_name,
            record.to_dict(),
            request_id,
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish request headers to the configured stream."""
        if not config.kinesis.request_headers_stream_name:
            logger.warning("Request headers stream not configured," " skipping publish")
            return False

        record = RequestHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self._publish_record(
            config.kinesis.request_headers_stream_name,
            record.to_dict(),
            request_id,
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_body(
        self,
        request_id: str,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        num_chunks: int,
    ) -> bool:
        """Publish request body to the configured stream."""
        if not config.kinesis.request_body_stream_name:
            logger.warning("Request body stream not configured," " skipping publish")
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
        )

        return await self._publish_record(
            config.kinesis.request_body_stream_name,
            record.to_dict(),
            request_id,
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish request trailers to the configured stream."""
        if not config.kinesis.request_trailers_stream_name:
            logger.warning(
                "Request trailers stream not configured," " skipping publish"
            )
            return False

        record = RequestTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self._publish_record(
            config.kinesis.request_trailers_stream_name,
            record.to_dict(),
            request_id,
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish response headers to the configured stream."""
        if not config.kinesis.response_headers_stream_name:
            logger.warning(
                "Response headers stream not configured," " skipping publish"
            )
            return False

        record = ResponseHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self._publish_record(
            config.kinesis.response_headers_stream_name,
            record.to_dict(),
            request_id,
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_body(
        self,
        request_id: str,
        body_bytes: bytes,
        timestamp: str,
        chunk_id: int,
        num_chunks: int,
    ) -> bool:
        """Publish response body to the configured stream."""
        if not config.kinesis.response_body_stream_name:
            logger.warning("Response body stream not configured," " skipping publish")
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
        )

        return await self._publish_record(
            config.kinesis.response_body_stream_name,
            record.to_dict(),
            request_id,
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish response trailers to the configured stream."""
        if not config.kinesis.response_trailers_stream_name:
            logger.warning(
                "Response trailers stream not configured," " skipping publish"
            )
            return False

        record = ResponseTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        return await self._publish_record(
            config.kinesis.response_trailers_stream_name,
            record.to_dict(),
            request_id,
        )
