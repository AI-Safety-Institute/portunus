"""Backend factory functions for Portunus.

Backends are selected via config (PORTUNUS_AUTH_BACKEND,
PORTUNUS_LOG_BACKEND). Auth and log backends are independently
configurable.
"""

import logging

from portunus.backends.protocols import AuthBackend, StreamPublisher
from portunus.config import PortunusConfig

logger = logging.getLogger("api.access")

__all__ = [
    "AuthBackend",
    "StreamPublisher",
    "get_auth_backend",
    "get_stream_publisher",
]


def get_auth_backend(cfg: PortunusConfig) -> AuthBackend:
    """Create an auth backend based on config.

    Args:
        cfg: Application config (reads auth_backend and aws settings).

    Returns:
        An AuthBackend implementation.

    Raises:
        ValueError: If the configured backend is unknown.
    """
    backend = cfg.auth_backend
    if backend == "aws":
        from portunus.backends.aws.auth import AwsAuthBackend

        return AwsAuthBackend(
            role_pattern=cfg.aws.identity_role_pattern,
        )
    raise ValueError(f"Unknown auth backend: {backend!r}")


def get_stream_publisher(cfg: PortunusConfig) -> StreamPublisher:
    """Create a stream publisher based on config.

    Args:
        cfg: Application config (reads log_backend).

    Returns:
        A StreamPublisher implementation.

    Raises:
        ValueError: If the configured backend is unknown.
    """
    backend = cfg.log_backend
    if backend == "kinesis":
        from portunus.backends.aws.publisher import (
            KinesisPublisher,
        )

        return KinesisPublisher()
    if backend == "debug":
        from portunus.backends.debug.publisher import DebugPublisher

        return DebugPublisher()
    raise ValueError(f"Unknown log backend: {backend!r}")
