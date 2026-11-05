"""Separate audit admission preserves the authentication boundary."""

import asyncio

import grpc
import pytest
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.service.ext_proc.v3 import (
    external_processor_pb2,
    external_processor_pb2_grpc,
)
from grpc_health.v1 import health_pb2, health_pb2_grpc

from portunus.config import GrpcConfig, KinesisConfig, config
from portunus.grpc.server import start_grpc_server, stop_grpc_server


async def discard_batch(stream, records):
    return len(records)


@pytest.mark.asyncio
async def test_separate_listeners_keep_services_and_channel_auth_separate(
    unused_tcp_port_factory, monkeypatch
):
    auth_port, audit_port = unused_tcp_port_factory(), unused_tcp_port_factory()
    key = "synthetic-test-channel-key"
    monkeypatch.setattr(config.grpc, "proxy_api_key", key)

    class Publisher:
        put_records = staticmethod(discard_batch)

    runtime = await start_grpc_server(
        config=GrpcConfig(
            enabled=True,
            port=auth_port,
            audit_port=audit_port,
            proxy_api_key=key,
            publish_workers=1,
        ),
        kinesis=KinesisConfig(
            **{
                name + "_stream_name": name
                for name in (
                    "metadata",
                    "request_headers",
                    "request_body",
                    "request_trailers",
                    "response_headers",
                    "response_body",
                    "response_trailers",
                )
            }
        ),
        auth_service=object(),
        publish_service=Publisher(),
    )

    async def messages():
        yield external_processor_pb2.ProcessingRequest()

    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{auth_port}") as auth_channel:
            health = health_pb2_grpc.HealthStub(auth_channel)
            result = await health.Check(health_pb2.HealthCheckRequest(), timeout=2)
            assert result.status == health_pb2.HealthCheckResponse.SERVING
            auth = external_auth_pb2_grpc.AuthorizationStub(auth_channel)
            response = await auth.Check(external_auth_pb2.CheckRequest(), timeout=2)
            assert response.HasField("denied_response")
            audit = external_processor_pb2_grpc.ExternalProcessorStub(auth_channel)
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await audit.Process(messages(), timeout=2).read()
            assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED

        async with grpc.aio.insecure_channel(
            f"127.0.0.1:{audit_port}"
        ) as audit_channel:
            auth = external_auth_pb2_grpc.AuthorizationStub(audit_channel)
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await auth.Check(external_auth_pb2.CheckRequest(), timeout=2)
            assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
            audit = external_processor_pb2_grpc.ExternalProcessorStub(audit_channel)
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await audit.Process(messages(), timeout=2).read()
            assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED
    finally:
        await stop_grpc_server(runtime, 1)


_ALL_STREAMS = KinesisConfig.model_validate(
    {
        name + "_stream_name": name
        for name in (
            "metadata",
            "request_headers",
            "request_body",
            "request_trailers",
            "response_headers",
            "response_body",
            "response_trailers",
        )
    }
)


class _Publisher:
    put_records = staticmethod(discard_batch)


async def _unary_messages():
    yield external_processor_pb2.ProcessingRequest()


async def _health(channel) -> int:
    health = health_pb2_grpc.HealthStub(channel)
    result = await health.Check(health_pb2.HealthCheckRequest(service=""), timeout=2)
    return result.status


@pytest.mark.asyncio
async def test_auth_role_serves_only_ext_authz_and_needs_no_kinesis(
    unused_tcp_port_factory, monkeypatch
):
    port = unused_tcp_port_factory()
    key = "synthetic-test-channel-key"
    monkeypatch.setattr(config.grpc, "proxy_api_key", key)

    runtime = await start_grpc_server(
        config=GrpcConfig(
            enabled=True,
            role="auth",
            port=port,
            audit_port=unused_tcp_port_factory(),
            proxy_api_key=key,
            publish_workers=1,
        ),
        kinesis=KinesisConfig(),
        auth_service=object(),
        publish_service=_Publisher(),
    )
    assert runtime is not None
    assert runtime.audit_server is None
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            assert await _health(channel) == health_pb2.HealthCheckResponse.SERVING
            auth = external_auth_pb2_grpc.AuthorizationStub(channel)
            response = await auth.Check(external_auth_pb2.CheckRequest(), timeout=2)
            assert response.HasField("denied_response")
            audit = external_processor_pb2_grpc.ExternalProcessorStub(channel)
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await audit.Process(_unary_messages(), timeout=2).read()
            assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
    finally:
        await stop_grpc_server(runtime, 1)


@pytest.mark.asyncio
async def test_audit_role_serves_only_ext_proc_on_audit_port(
    unused_tcp_port_factory, monkeypatch
):
    port, audit_port = unused_tcp_port_factory(), unused_tcp_port_factory()
    key = "synthetic-test-channel-key"
    monkeypatch.setattr(config.grpc, "proxy_api_key", key)

    class _DownRedis:
        async def health_check(self) -> bool:
            return False

    class _PublisherWithState(_Publisher):
        state_service = _DownRedis()

    runtime = await start_grpc_server(
        config=GrpcConfig(
            enabled=True,
            role="audit",
            port=port,
            audit_port=audit_port,
            proxy_api_key=key,
            publish_workers=1,
        ),
        kinesis=_ALL_STREAMS,
        auth_service=object(),
        publish_service=_PublisherWithState(),
    )
    assert runtime is not None
    # Health reflects this process only: a down Redis does not pull it.
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{audit_port}") as channel:
            assert await _health(channel) == health_pb2.HealthCheckResponse.SERVING
            auth = external_auth_pb2_grpc.AuthorizationStub(channel)
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await auth.Check(external_auth_pb2.CheckRequest(), timeout=2)
            assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
            audit = external_processor_pb2_grpc.ExternalProcessorStub(channel)
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await audit.Process(_unary_messages(), timeout=2).read()
            assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED

        # Nothing listens on the auth port: that is the other process's.
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await _health(channel)
            assert error.value.code() == grpc.StatusCode.UNAVAILABLE
    finally:
        await stop_grpc_server(runtime, 1)


@pytest.mark.asyncio
async def test_health_ignores_redis_and_reports_only_this_process(
    unused_tcp_port_factory, monkeypatch
):
    """An auth process stays ready while Redis is down; draining clears it.

    Every task shares one Redis, so a Redis-gated health signal would
    de-register the whole fleet at once. Health follows only the process's own
    listeners.
    """
    port = unused_tcp_port_factory()
    key = "synthetic-test-channel-key"
    monkeypatch.setattr(config.grpc, "proxy_api_key", key)

    class _DownRedis:
        async def health_check(self) -> bool:
            return False

    class _PublisherWithState(_Publisher):
        state_service = _DownRedis()

    runtime = await start_grpc_server(
        config=GrpcConfig(
            enabled=True, role="auth", port=port, proxy_api_key=key, publish_workers=1
        ),
        kinesis=KinesisConfig(),
        auth_service=object(),
        publish_service=_PublisherWithState(),
    )
    assert runtime is not None
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            for _ in range(3):
                assert await _health(channel) == health_pb2.HealthCheckResponse.SERVING
                await asyncio.sleep(0.05)
    finally:
        await stop_grpc_server(runtime, 1)
    status = await runtime.health_servicer.Check(
        health_pb2.HealthCheckRequest(service=""), None
    )
    assert status.status == health_pb2.HealthCheckResponse.NOT_SERVING


@pytest.mark.asyncio
async def test_audit_role_still_requires_kinesis_config():
    with pytest.raises(RuntimeError, match="Kinesis"):
        await start_grpc_server(
            config=GrpcConfig(
                enabled=True,
                role="audit",
                proxy_api_key="synthetic-test-channel-key",
            ),
            kinesis=KinesisConfig(),
            auth_service=object(),
            publish_service=_Publisher(),
        )


async def _reflected_services(channel) -> set[str]:
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    stub = reflection_pb2_grpc.ServerReflectionStub(channel)
    request = reflection_pb2.ServerReflectionRequest(list_services="")
    responses = [r async for r in stub.ServerReflectionInfo(iter([request]), timeout=2)]
    return {s.name for s in responses[0].list_services_response.service}


@pytest.mark.asyncio
@pytest.mark.parametrize("split", [False, True], ids=["shared", "split"])
async def test_every_listener_reflects_its_services_and_answers_health(
    unused_tcp_port_factory, monkeypatch, split
):
    """Envoy may target either port, so each must answer reflection and health."""
    auth_port = unused_tcp_port_factory()
    audit_port = unused_tcp_port_factory() if split else None
    key = "synthetic-test-channel-key"
    monkeypatch.setattr(config.grpc, "proxy_api_key", key)
    runtime = await start_grpc_server(
        config=GrpcConfig(
            enabled=True,
            port=auth_port,
            audit_port=audit_port,
            proxy_api_key=key,
            publish_workers=1,
        ),
        kinesis=_ALL_STREAMS,
        auth_service=object(),
        publish_service=_Publisher(),
    )
    assert runtime is not None
    auth, proc = (
        "envoy.service.auth.v3.Authorization",
        "envoy.service.ext_proc.v3.ExternalProcessor",
    )
    common = {"grpc.health.v1.Health", "grpc.reflection.v1alpha.ServerReflection"}
    expected = {auth_port: {auth} | common | (set() if split else {proc})}
    if audit_port is not None:
        expected[audit_port] = {proc} | common
    try:
        for port, services in expected.items():
            async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
                assert await _reflected_services(channel) == services, port
                assert await _health(channel) == health_pb2.HealthCheckResponse.SERVING
    finally:
        await stop_grpc_server(runtime, 1)
    status = await runtime.health_servicer.Check(
        health_pb2.HealthCheckRequest(service=""), None
    )
    assert status.status == health_pb2.HealthCheckResponse.NOT_SERVING
