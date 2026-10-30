"""
Utility functions for the Portunus.

This module contains utility functions that are used throughout the Portunus,
particularly for AWS interactions like getting temporary credentials.
"""

import datetime
import logging

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
    "generate_iso_timestamp",
    "unix_timestamp_to_iso",
    "chunk_body_data",
]


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
