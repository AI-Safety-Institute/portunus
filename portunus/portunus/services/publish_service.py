"""
Publish service module.

This module contains the PublishService class, which is responsible for
publishing log data to Kinesis streams for long-term storage.
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
    Service for publishing log events to external streams.

    This service handles publishing to:
    - Kinesis Data Streams for long-term data storage

    Attributes:
        state_service: The StateService for AWS client access
    """

    def __init__(self, state_service: Optional[StateService] = None):
        """Initialize the PublishService."""
        self.state_service = state_service or StateService()

    async def publish_to_kinesis_data_stream(
        self,
        stream_name: str,
        record_data: Dict[str, Any],
        partition_key: str,
    ) -> bool:
        """
        Publish a single record to a Kinesis Data Stream.

        Args:
            stream_name: Name of the Kinesis Data Stream (without prefix)
            record_data: Data to publish
            partition_key: Partition key for the record

        Returns:
            True if successful

        Raises:
            ServiceError: If publishing fails
        """
        if not stream_name:
            logger.warning(
                f"Stream name not configured, skipping publish to {stream_name}"
            )
            return False

        # Add throttling in local mode to prevent overwhelming LocalStack
        # LocalStack's Kinesis implementation can drop requests under high load
        if config.aws.endpoint_url:
            await asyncio.sleep(1.0)

        try:
            async with await self.state_service.get_kinesis_client() as kinesis_client:
                # Prepare and serialize the record data
                data_bytes = json.dumps(record_data, default=str).encode("utf-8")

                response = await kinesis_client.put_record(
                    StreamName=stream_name,
                    Data=data_bytes,
                    PartitionKey=partition_key,
                )

                shard_id = response.get("ShardId")
                sequence_number = response.get("SequenceNumber")
                logger.info(
                    f"Published record to Kinesis Data Stream {stream_name} "
                    f"with ShardId {shard_id} and SequenceNumber "
                    f"{sequence_number[:8]}..."
                )
                return True

        except TimeoutError as e:
            logger.exception(
                f"Timeout while publishing to Kinesis Data Stream {stream_name}: {e}"
            )
            raise e
        except Exception as e:
            logger.exception(
                f"Failed to publish to Kinesis Data Stream {stream_name}: {e}"
            )
            raise ServiceError(f"Failed to publish to Kinesis Data Stream: {e}")

    @xray_recorder.capture_async()  # type: ignore
    async def publish_metadata(
        self,
        request_id: str,
        timestamp: str,
        principal_info: Dict[str, Any],
        secret_arn: Optional[str] = None,
    ) -> bool:
        """Publish metadata to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            timestamp: ISO-8601 formatted timestamp
            principal_info: Principal information dictionary
            secret_arn: Full ARN of the secret used for API key (for usage tracking)
        """
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
            secret_arn=secret_arn,
        )

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.metadata_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish request headers to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            headers: Request headers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.kinesis.request_headers_stream_name:
            logger.warning("Request headers stream not configured, skipping publish")
            return False

        record = RequestHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.request_headers_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
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
        """Publish request body to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            body_bytes: Raw body bytes
            timestamp: ISO-8601 formatted timestamp
            chunk_id: Index of this chunk (0-based)
            num_chunks: Total number of chunks
        """
        if not config.kinesis.request_body_stream_name:
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

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.request_body_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_request_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish request trailers to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            trailers: Request trailers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.kinesis.request_trailers_stream_name:
            logger.warning("Request trailers stream not configured, skipping publish")
            return False

        record = RequestTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.request_trailers_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_headers(
        self,
        request_id: str,
        headers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish response headers to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            headers: Response headers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.kinesis.response_headers_stream_name:
            logger.warning("Response headers stream not configured, skipping publish")
            return False

        record = ResponseHeadersRecord(
            request_id=request_id,
            raw_headers=headers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.response_headers_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
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
        """Publish response body to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            body_bytes: Raw body bytes
            timestamp: ISO-8601 formatted timestamp
            chunk_id: Index of this chunk (0-based)
            num_chunks: Total number of chunks
        """
        if not config.kinesis.response_body_stream_name:
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

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.response_body_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
        )

    @xray_recorder.capture_async()  # type: ignore
    async def publish_response_trailers(
        self,
        request_id: str,
        trailers: Dict[str, str],
        timestamp: str,
    ) -> bool:
        """Publish response trailers to Kinesis stream with ISO-8601 timestamps.

        Args:
            request_id: Unique request ID
            trailers: Response trailers dictionary
            timestamp: ISO-8601 formatted timestamp
        """
        if not config.kinesis.response_trailers_stream_name:
            logger.warning("Response trailers stream not configured, skipping publish")
            return False

        record = ResponseTrailersRecord(
            request_id=request_id,
            trailers=trailers,
            timestamp=timestamp,
            published_at=generate_iso_timestamp(),
        )

        # Use the stream name without prefix for the Kinesis Data Stream
        data_stream_name = config.kinesis.response_trailers_stream_name
        return await self.publish_to_kinesis_data_stream(
            data_stream_name, record.to_dict(), request_id
        )
