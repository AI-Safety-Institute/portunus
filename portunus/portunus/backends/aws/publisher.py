"""AWS Kinesis Data Streams publisher backend."""

import asyncio
import json
import logging
from typing import Any

import aiobotocore.session

from portunus.config import config
from portunus.exceptions import ServiceError

logger = logging.getLogger("api.access")


class KinesisPublisher:
    """Publishes records to AWS Kinesis Data Streams."""

    def __init__(self) -> None:
        self.boto_session = aiobotocore.session.get_session()

    async def publish(
        self,
        stream_name: str,
        record_data: dict[str, Any],
        partition_key: str,
    ) -> bool:
        """Publish a single record to a Kinesis Data Stream."""
        if not stream_name:
            logger.warning("Stream name not configured, skipping publish")
            return False

        # Throttle in local mode to prevent overwhelming LocalStack
        if config.aws.endpoint_url:
            await asyncio.sleep(1.0)

        try:
            async with self.boto_session.create_client("kinesis") as kinesis_client:
                data_bytes = json.dumps(record_data, default=str).encode("utf-8")

                response = await kinesis_client.put_record(
                    StreamName=stream_name,
                    Data=data_bytes,
                    PartitionKey=partition_key,
                )

                shard_id = response.get("ShardId")
                seq = response.get("SequenceNumber")
                logger.info(
                    f"Published record to Kinesis"
                    f" {stream_name}"
                    f" ShardId {shard_id}"
                    f" Seq {seq[:8]}..."
                )
                return True

        except TimeoutError as e:
            logger.exception(f"Timeout publishing to Kinesis" f" {stream_name}: {e}")
            raise
        except Exception as e:
            logger.exception(f"Failed to publish to Kinesis" f" {stream_name}: {e}")
            raise ServiceError(f"Failed to publish to Kinesis: {e}")
