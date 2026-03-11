"""
Utility functions for the Portunus.

This module contains utility functions that are used throughout the Portunus,
particularly for AWS interactions like getting temporary credentials.
"""

import asyncio
import datetime
import logging
import time

import boto3
from aws_xray_sdk.core import xray_recorder

# Import function for implementation
# Re-export these functions for backwards compatibility
from portunus.services.arn_service import (
    extract_arn_parts,
    get_role_arn,
    parse_identity_from_arn,
)
from portunus.services.payload_service import (
    decode_payload,
)

logger = logging.getLogger("api.access")

# This comment ensures these imports are marked as used
__all__ = [
    "extract_arn_parts",
    "get_role_arn",
    "parse_identity_from_arn",
    "decode_payload",
    "get_current_session_arn",
    "generate_iso_timestamp",
    "unix_timestamp_to_iso",
    "chunk_body_data",
]


def get_current_session_arn() -> str:
    """Get the ARN of the current session.

    Returns:
        str: The ARN of the current session.
    """
    sts_client = boto3.client("sts")
    response = sts_client.get_caller_identity()
    return response["Arn"]


@xray_recorder.capture_async()  # type: ignore
async def wait_until(
    condition_func, timeout=3.0, interval=0.05, error_message=None
) -> None:
    """
    Wait until a condition function returns True or timeout is reached.

    Args:
        condition_func: A callable async function that returns a boolean.
        timeout: Maximum time to wait in seconds (default: 3.0).
        interval: Time between checks in seconds (default: 0.05).
        error_message: Optional message to include in the exception if timeout
                        reached.

    Returns:
        None when condition is met, raises an exception if timeout or cancelled.

    Raises:
        TimeoutError: If the condition is not met within the timeout period.
    """
    try:
        start_time = time.time()
        while True:
            try:
                if await condition_func():
                    return None
            except Exception as e:
                logger.warning(f"Error checking condition: {e}")

            # Check for timeout
            if time.time() - start_time > timeout:
                msg = "Condition not met within timeout period"
                if error_message:
                    msg = f"{error_message} - {msg}"
                logger.warning(msg)
                raise TimeoutError(msg)

            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError as e:
                logger.warning(
                    f"wait_until cancelled while waiting for {error_message}"
                )
                raise e
    except Exception as e:
        logger.error(f"Unexpected error in wait_until: {e}")
        raise e


def generate_iso_timestamp() -> str:
    """Generate an ISO-8601 timestamp string for Kinesis partitioning.

    Returns a string in format YYYY-MM-DDThh:mm:ss.sssZ which works with the
    Kinesis metadata extraction query for partitioning by year, month, day, hour.

    Returns:
        str: ISO-8601 formatted timestamp with millisecond precision
    """
    return (
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[
            :-3
        ]
        + "Z"
    )


def unix_timestamp_to_iso(unix_timestamp: int) -> str:
    """Convert a Unix timestamp to ISO-8601 format for Kinesis partitioning.

    Args:
        unix_timestamp: Unix timestamp (seconds since epoch)

    Returns:
        str: ISO-8601 formatted timestamp with millisecond precision
    """
    dt = datetime.datetime.fromtimestamp(unix_timestamp, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def chunk_body_data(
    body_bytes: bytes, max_record_size: int | None = None
) -> list[bytes]:
    """Chunk body data into pieces that fit within Kinesis limits.

    Args:
        body_bytes: The body data to chunk
        max_record_size: Maximum size for a single Kinesis record.
        If None, uses config value.

    Returns a list of raw byte chunks.
    Chunk order in the list determines the chunk_id.
    """
    if max_record_size is None:
        from portunus.config import config

        max_record_size = config.kinesis.max_record_size

    max_b64_per_chunk = max_record_size - 100
    safe_raw_chunk_size = (max_b64_per_chunk // 4) * 3

    chunks = []
    for i in range(0, len(body_bytes), safe_raw_chunk_size):
        chunks.append(body_bytes[i : i + safe_raw_chunk_size])

    return chunks
