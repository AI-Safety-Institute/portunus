"""WebSocket relay module for Portunus.

Provides bidirectional WebSocket proxying with authentication,
per-message logging to Firehose, and token usage extraction.
"""

import enum


class WsCloseCode(enum.IntEnum):
    """WebSocket close status codes used by the relay."""

    NORMAL = 1000
    GOING_AWAY = 1001
    INTERNAL_ERROR = 1011
    TRY_AGAIN_LATER = 1013
    AUTH_FAILED = 4001
    FORBIDDEN = 4003
