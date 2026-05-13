"""Pre-shared-key check for Envoy proxy → Portunus gRPC calls.

The Service Connect namespace gates network reachability, but it's
broader than the api-key-proxy fleet — any tenant-001 service is in
the same namespace. ``x-portunus-proxy-key`` is the identity factor
that proves the caller is a sanctioned proxy, paired with the AWS
credential payload that proves authorisation for a specific
``secret_arn``.

Envoy injects the key via ``grpc_service.initial_metadata`` on both
the ext_authz and ext_proc filter configs:

    grpc_service:
      envoy_grpc:
        cluster_name: portunus_grpc_cluster
      initial_metadata:
      - key: x-portunus-proxy-key
        value: "${PORTUNUS_API_KEY}"

The servicer reads it from ``context.invocation_metadata()`` and
matches against the configured expected value. An empty expected
value disables validation — only safe in tests.
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
    """Return the proxy's target_host from gRPC invocation metadata.

    Envoy injects this via ``initial_metadata`` on the ext_authz filter
    so it's authoritative from the proxy config. Clients have no path
    to the gRPC channel; reading from invocation_metadata closes the
    HTTP-header forgery vector that bypassed secret.host validation.
    """
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
    """Constant-time comparison; treats empty ``expected`` as "validation off"."""
    if not expected:
        return True  # validation disabled (test-only mode)
    if not received:
        return False
    return hmac.compare_digest(received, expected)
