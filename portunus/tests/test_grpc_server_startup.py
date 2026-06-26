"""Tests for the gRPC server's fail-closed checks at startup."""

from __future__ import annotations

import pytest

from portunus.config import GrpcConfig
from portunus.grpc import server as grpc_server
from portunus.grpc.server import start_grpc_server


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
async def test_disabled_server_returns_none_without_checking_proxy_key():
    """When ``enabled=False`` the fail-closed check is bypassed.

    The empty-key fail-closed only applies once we'd actually start
    serving, so a tenant that has GRPC_ENABLED=false (i.e. running
    only the FastAPI side) doesn't crash on config validation.
    """
    config = GrpcConfig(enabled=False)
    assert (
        await start_grpc_server(
            config=config,
            auth_service=_FakeAuthService(),  # type: ignore[arg-type]
            publish_service=_FakePublishService(),  # type: ignore[arg-type]
        )
        is None
    )


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
            auth_service=_FakeAuthService(),  # type: ignore[arg-type]
            publish_service=_FakePublishService(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_enabled_with_non_empty_key_does_not_raise():
    """A configured key satisfies the check; server attempts startup."""
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="abc",
        proxy_api_key_optional=False,
        # Use an ephemeral port to avoid clashing with anything else
        # the test runner has bound. Range 30000+ is safely above the
        # well-known services.
        port=50051,
    )
    runtime = await start_grpc_server(
        config=config,
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
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        publish_service=_FakePublishService(),  # type: ignore[arg-type]
    )
    try:
        assert runtime is not None
    finally:
        if runtime is not None:
            await runtime.server.stop(grace=None)
            await runtime.publish_queue.stop(drain_timeout=0.1)
