"""Debug stream publisher for development and testing without Kinesis."""

import logging
from typing import Any

logger = logging.getLogger("api.access")


class DebugPublisher:
    """Logs records at DEBUG level and returns True. No external calls."""

    async def publish(
        self,
        stream_name: str,
        record_data: dict[str, Any],
        partition_key: str,
    ) -> bool:
        """Log the record and return success."""
        logger.debug(
            f"[debug] Would publish to {stream_name}"
            f" partition={partition_key}"
            f" keys={list(record_data.keys())}"
        )
        return True
