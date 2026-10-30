"""WebSocket frame observer for ext_proc streams.

Wraps :mod:`wsproto` to surface logical WebSocket frames from raw,
possibly-fragmented, possibly-deflate-compressed bytes carried over
``ext_proc`` body events for upgraded streams.
"""

from __future__ import annotations

from enum import Enum


class Direction(Enum):
    """Stream direction for frame observation."""

    REQUEST = "request"  # client → server
    RESPONSE = "response"  # server → client
