"""Tests for the gRPC server's fail-closed checks at startup."""

from __future__ import annotations

import grpc
import pytest
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

from portunus.config import GrpcConfig
from portunus.grpc.server import start_grpc_server, stop_grpc_server


class _FakeAuthService:
    """Minimal stand-in — ``start_grpc_server`` only stores the reference."""


@pytest.mark.asyncio
async def test_enabled_with_empty_key_and_optional_unset_raises_runtimeerror():
    """Empty key with optional=False refuses to start, before binding a port."""
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="",
        proxy_api_key_optional=False,
    )
    with pytest.raises(RuntimeError, match="GRPC_PROXY_API_KEY"):
        await start_grpc_server(
            config=config,
            auth_service=_FakeAuthService(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_enabled_with_short_key_raises_runtimeerror():
    """A configured-but-trivial key (< 16 bytes) fails the boot floor.

    Such a key passes the empty-key guard but is no real identity gate, so a
    fat-fingered placeholder must fail at boot.
    """
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="abc",
        proxy_api_key_optional=False,
    )
    with pytest.raises(RuntimeError, match="16 bytes"):
        await start_grpc_server(
            config=config,
            auth_service=_FakeAuthService(),  # type: ignore[arg-type]
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
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
    )
    try:
        assert runtime is not None
    finally:
        if runtime is not None:
            await runtime.server.stop(grace=None)


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
    )
    try:
        assert runtime is not None
    finally:
        if runtime is not None:
            await runtime.server.stop(grace=None)


@pytest.mark.asyncio
async def test_health_is_serving_once_listening_and_not_serving_after_stop(
    unused_tcp_port,
):
    """The default health service tracks only this process's listener."""
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="local-health-test-key-0",
        port=unused_tcp_port,
    )
    runtime = await start_grpc_server(
        config=config,
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
    )
    assert runtime is not None
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{unused_tcp_port}") as channel:
            reply = await health_pb2_grpc.HealthStub(channel).Check(
                health_pb2.HealthCheckRequest(service=""), timeout=2
            )
        assert reply.status == health_pb2.HealthCheckResponse.SERVING
    finally:
        await stop_grpc_server(runtime, grace_seconds=0)
    status = await runtime.health_servicer.Check(
        health_pb2.HealthCheckRequest(service=""), None
    )
    assert status.status == health_pb2.HealthCheckResponse.NOT_SERVING


@pytest.mark.asyncio
async def test_reflection_discovers_auth_and_health_services(unused_tcp_port):
    config = GrpcConfig(
        enabled=True,
        proxy_api_key="local-reflection-test-key",
        port=unused_tcp_port,
    )
    runtime = await start_grpc_server(
        config=config,
        auth_service=_FakeAuthService(),  # type: ignore[arg-type]
    )
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{unused_tcp_port}") as channel:
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            responses = [
                response
                async for response in stub.ServerReflectionInfo(
                    iter([reflection_pb2.ServerReflectionRequest(list_services="")]),
                    timeout=2,
                )
            ]
        assert len(responses) == 1
        assert {
            service.name for service in responses[0].list_services_response.service
        } == {
            "envoy.service.auth.v3.Authorization",
            "grpc.health.v1.Health",
            "grpc.reflection.v1alpha.ServerReflection",
        }
    finally:
        await stop_grpc_server(runtime, grace_seconds=0)
