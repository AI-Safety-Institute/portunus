"""
Publish service module.

This module contains the PublishService class, which is responsible for
publishing audit records straight to Kinesis Firehose delivery streams
via direct-PUT. Firehose handles batching, retry, and DLQ server-side,
so the client just fire-and-forgets a single ``PutRecord`` per event.
"""

import asyncio
import base64
import json
import logging
from typing import Any, Dict, Optional

from aws_xray_sdk.core import xray_recorder

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
)
from portunus.services.state_service import StateService
from portunus.util import generate_iso_timestamp

logger = logging.getLogger("api.access")


class PublishService:
    """
    Service for publishing log events to Firehose delivery streams.

    Records are sent via Firehose direct-PUT (one ``PutRecord`` per event).
    Firehose buffers and lands them on S3 in the same Parquet layout used
    upstream of the akp Glue ETL, so downstream consumers are unaffected.

    Attributes:
        state_service: The StateService for AWS client access
    """

    def __init__(self, state_service: Optional[StateService] = None):
        """Initialize the PublishService."""
        self.state_service = state_service or StateService()

    async def publish_to_firehose(
        self,
        stream_name: str,
        record_data: Dict[str, Any],
        partition_key: str,
    ) -> bool:
        """
        Publish a single record to a Firehose delivery stream via direct-PUT.

        Firehose has no shards so there's no partition key on the wire; the
        ``partition_key`` argument is retained for log correlation with the
        caller's request_id and is otherwise unused.

        Args:
            stream_name: Name of the Firehose delivery stream
            record_data: Data to publish
            partition_key: Request ID used for log correlation only

        Returns:
            True if successful, False if ``stream_name`` is unset

        Raises:
            ServiceError: If publishing fails
        """
        if not stream_name:
            logger.warning(
                f"Stream name not configured, skipping publish to {stream_name}"
            )
            return False

        # Throttle slightly in local mode so LocalStack's Firehose event
        # loop doesn't get starved by a burst from a single test run.
        if config.aws.endpoint_url:
            await asyncio.sleep(1.0)

        try:
            client_cm = await self.state_service.get_firehose_client()
            async with client_cm as firehose_client:
                # Prepare and serialize the record data
                data_bytes = json.dumps(record_data, default=str).encode("utf-8")

                response = await firehose_client.put_record(
                    DeliveryStreamName=stream_name,
                    Record={"Data": data_bytes},
                )

                record_id = response.get("RecordId", "")
                logger.info(
                    f"Published record to Firehose delivery stream {stream_name} "
                    f"with RecordId {record_id[:8]}... "
                    f"(correlation_id={partition_key})"
                )
                return True

        except TimeoutError as e:
            logger.exception(
                f"Timeout while publishing to Firehose delivery stream "
                f"{stream_name}: {e}"
            )
            raise e
        except Exception as e:
            logger.exception(
                f"Failed to publish to Firehose delivery stream {stream_name}: {e}"
            )
            raise ServiceError(f"Failed to publish to Firehose: {e}")

    @xray_recorder.capture_async()  # type: ignore
    async def publish_metadata(
        self,
        request_id: str,
        timestamp: str,
        principal_info: Dict[str, Any],
        secret_arn: Optional[str] = None,
    ) -> bool:
        """Publish metadata to a Firehose delivery stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            timestamp: ISO-8601 formatted timestamp
            principal_info: Principal information dictionary
            secret_arn: Full ARN of the secret used for API key (for usage tracking)
        """
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

        stream_name = config.firehose.metadata_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish request headers to a Firehose delivery stream.

        Args:
            request_id: Unique request ID
            headers: Request headers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.firehose.request_headers_stream_name:
            logger.warning("Request headers stream not configured, skipping publish")
            return False

        record = RequestHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        stream_name = config.firehose.request_headers_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
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
        """Publish request body to a Firehose delivery stream.

        Args:
            request_id: Unique request ID
            body_bytes: Raw body bytes
            timestamp: ISO-8601 formatted timestamp
            chunk_id: Index of this chunk (0-based)
            num_chunks: Total number of chunks
        """
        if not config.firehose.request_body_stream_name:
            logger.warning("Request body stream not configured, skipping publish")
            return False

        # Base64 encode for JSON serialization

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

        stream_name = config.firehose.request_body_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish request trailers to a Firehose delivery stream.

        Args:
            request_id: Unique request ID
            trailers: Request trailers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.firehose.request_trailers_stream_name:
            logger.warning("Request trailers stream not configured, skipping publish")
            return False

        record = RequestTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        stream_name = config.firehose.request_trailers_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish response headers to a Firehose delivery stream.

        Args:
            request_id: Unique request ID
            headers: Response headers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.firehose.response_headers_stream_name:
            logger.warning("Response headers stream not configured, skipping publish")
            return False

        record = ResponseHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        stream_name = config.firehose.response_headers_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
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
        """Publish response body to a Firehose delivery stream.

        Args:
            request_id: Unique request ID
            body_bytes: Raw body bytes
            timestamp: ISO-8601 formatted timestamp
            chunk_id: Index of this chunk (0-based)
            num_chunks: Total number of chunks
        """
        if not config.firehose.response_body_stream_name:
            logger.warning("Response body stream not configured, skipping publish")
            return False

        # Base64 encode for JSON serialization

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

        stream_name = config.firehose.response_body_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish response trailers to a Firehose delivery stream.

        Args:
            request_id: Unique request ID
            trailers: Response trailers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.firehose.response_trailers_stream_name:
            logger.warning("Response trailers stream not configured, skipping publish")
            return False

        record = ResponseTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        stream_name = config.firehose.response_trailers_stream_name
        return await self.publish_to_firehose(
            stream_name, record.to_dict(), request_id
        )
