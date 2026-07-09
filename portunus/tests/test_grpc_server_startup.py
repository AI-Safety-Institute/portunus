"""Tests for the gRPC server's fail-closed checks at startup."""

from __future__ import annotations

import pytest

from portunus.config import FirehoseConfig, GrpcConfig
from portunus.grpc import server as grpc_server
from portunus.grpc.server import start_grpc_server


def _configured_firehose() -> FirehoseConfig:
    """A FirehoseConfig with every required stream set.

    These tests exercise the proxy-key / message-limit checks, so the audit
    fail-fast guard must pass; the Firehose guard itself is covered in
    ``test_firehose_config_guard.py``.
    """
    return FirehoseConfig(
        metadata_stream_name="metadata",
        request_headers_stream_name="req-headers",
        request_body_stream_name="req-body",
        request_trailers_stream_name="req-trailers",
        response_headers_stream_name="resp-headers",
        response_body_stream_name="resp-body",
        response_trailers_stream_name="resp-trailers",
    )


class _FakeAuthService:
    """Minimal stand-in — ``start_grpc_server`` only stores the reference."""


class _FakePublishService:
    """Minimal stand-in for PublishService.

    ``start_grpc_server`` wires ``put_record_batch`` as the queue's
    batch_sender, so it must exist.
    """

    async def put_record_batch(self, stream_name: str, records: list[bytes]) -> int:
        return 0


def test_grpc_message_limit_has_signed_body_headroom():
    assert grpc_server._MAX_GRPC_MSG_BYTES == 64 * 1024 * 1024
    assert grpc_server._MAX_GRPC_MSG_BYTES > 32 * 1024 * 1024


@pytest.mark.asyncio
async def test_enabled_with_empty_key_and_optional_unset_raises_runtimeerror():
    """Production guard: empty key with optional=False refuses to start.

    The check fires before the server binds a port, so callers learn
    of the misconfiguration immediately rather than later when a real
    Envoy fails ``PERMISSION_DENIED`` on every call.
    """
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="",
        proxy_api_key_optional=False,
    )
    with pytest.raises(RuntimeError, match="GRPC_PROXY_API_KEY"):
        await start_grpc_server(
            config=config,
            firehose=_configured_firehose(),
            auth_service=_FakeAuthService(),  # type: ignore[arg-type]
            publish_service=_FakePublishService(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_enabled_with_short_key_raises_runtimeerror():
    """A configured-but-trivial key (< 16 bytes) fails the boot floor.

    ``GRPC_PROXY_API_KEY="x"`` passes the empty-key guard while providing
    no real channel-identity gate — a fat-fingered placeholder must fail
    at boot, not in a security review.
    """
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="abc",
        proxy_api_key_optional=False,
    )
    with pytest.raises(RuntimeError, match="16 bytes"):
        await start_grpc_server(
            config=config,
            firehose=_configured_firehose(),
            auth_service=_FakeAuthService(),  # type: ignore[arg-type]
            publish_service=_FakePublishService(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_enabled_with_non_empty_key_does_not_raise():
    """A configured key (>= the 16-byte floor) satisfies the check."""
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="a-real-proxy-key-with-length",
        proxy_api_key_optional=False,
        # Distinct high port to avoid clashing with the other startup tests.
        port=50051,
    )
    runtime = await start_grpc_server(
        config=config,
        firehose=_configured_firehose(),
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        publish_service=_FakePublishService(),  # type: ignore[arg-type]
    )
    try:
        assert runtime is not None
    finally:
        if runtime is not None:
            await runtime.server.stop(grace=None)
            await runtime.publish_queue.stop(drain_timeout=0.1)


@pytest.mark.asyncio
async def test_enabled_with_empty_key_but_optional_true_starts():
    """Explicit opt-out lets local dev / tests run without a key."""
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="",
        proxy_api_key_optional=True,
        port=50052,
    )
    runtime = await start_grpc_server(
        config=config,
        firehose=_configured_firehose(),
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        publish_service=_FakePublishService(),  # type: ignore[arg-type]
    )
    try:
        assert runtime is not None
    finally:
        if runtime is not None:
            await runtime.server.stop(grace=None)
            await runtime.publish_queue.stop(drain_timeout=0.1)
