"""Pre-shared-key check for Envoy proxy → Portunus gRPC calls.

Envoy injects ``x-portunus-proxy-key`` (and ``x-portunus-target-host``) via gRPC
``initial_metadata``. Reading from ``invocation_metadata`` is forgery-resistant
because clients cannot reach the gRPC channel. An empty expected key disables
validation (tests only).
"""

from __future__ import annotations

import hmac
from typing import Optional

import grpc

PROXY_KEY_HEADER = "x-portunus-proxy-key"
TARGET_HOST_HEADER = "x-portunus-target-host"


def extract_proxy_key(context: grpc.aio.ServicerContext) -> Optional[str]:
    """Return the proxy key from invocation metadata, or ``None`` if absent."""
    return _read_metadata(context, PROXY_KEY_HEADER)


def extract_target_host(context: grpc.aio.ServicerContext) -> Optional[str]:
    """Return the proxy's target_host from gRPC invocation metadata."""
    return _read_metadata(context, TARGET_HOST_HEADER)


def _read_metadata(context: grpc.aio.ServicerContext, key_name: str) -> Optional[str]:
    try:
        for entry in context.invocation_metadata() or []:
            key, value = entry[0], entry[1]
            if key.lower() == key_name:
                return value if isinstance(value, str) else value.decode("utf-8")
    except Exception:
        return None
    return None


def is_valid_proxy_key(received: Optional[str], expected: str) -> bool:
    """Constant-time comparison; empty ``expected`` disables validation."""
    if not expected:
        return True
    if not received:
        return False
    return hmac.compare_digest(received, expected)
