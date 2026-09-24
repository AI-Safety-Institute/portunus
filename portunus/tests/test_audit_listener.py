"""Separate audit admission preserves the authentication boundary."""

import grpc
import pytest
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.service.ext_proc.v3 import (
    external_processor_pb2,
    external_processor_pb2_grpc,
)
from grpc_health.v1 import health_pb2, health_pb2_grpc

from portunus.config import FirehoseConfig, GrpcConfig, config
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
        put_record_batch = staticmethod(discard_batch)

    runtime = await start_grpc_server(
        config=GrpcConfig(
            enabled=True,
            port=auth_port,
            audit_port=audit_port,
            proxy_api_key=key,
            publish_workers=1,
            health_check_interval_seconds=0,
        ),
        firehose=FirehoseConfig(
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


_ALL_STREAMS = FirehoseConfig(
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
)


class _Publisher:
    put_record_batch = staticmethod(discard_batch)


async def _unary_messages():
    yield external_processor_pb2.ProcessingRequest()


async def _readiness(channel) -> int:
    health = health_pb2_grpc.HealthStub(channel)
    result = await health.Check(
        health_pb2.HealthCheckRequest(service="readiness"), timeout=2
    )
    return result.status


@pytest.mark.asyncio
async def test_auth_role_serves_only_ext_authz_and_needs_no_firehose(
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
            health_check_interval_seconds=0,
        ),
        firehose=FirehoseConfig(),
        auth_service=object(),
        publish_service=_Publisher(),
    )
    assert runtime is not None
    assert runtime.audit_server is None
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            assert await _readiness(channel) == health_pb2.HealthCheckResponse.SERVING
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
async def test_audit_role_serves_only_ext_proc_on_audit_port_without_redis_monitor(
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
            health_check_interval_seconds=0.01,
            health_check_failure_threshold=1,
        ),
        firehose=_ALL_STREAMS,
        auth_service=object(),
        publish_service=_PublisherWithState(),
    )
    assert runtime is not None
    # Audit never authenticates, so a Redis outage must not pull it.
    assert runtime.health_monitor is None
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{audit_port}") as channel:
            assert await _readiness(channel) == health_pb2.HealthCheckResponse.SERVING
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
                await _readiness(channel)
            assert error.value.code() == grpc.StatusCode.UNAVAILABLE
    finally:
        await stop_grpc_server(runtime, 1)


@pytest.mark.asyncio
async def test_audit_role_still_requires_firehose_config():
    with pytest.raises(RuntimeError, match="Firehose"):
        await start_grpc_server(
            config=GrpcConfig(
                enabled=True,
                role="audit",
                proxy_api_key="synthetic-test-channel-key",
            ),
            firehose=FirehoseConfig(),
            auth_service=object(),
            publish_service=_Publisher(),
        )


def test_split_roles_register_disjoint_metric_sources(capsys):
    """Each role emits only the metrics it owns.

    Neither role then reports the other's structural zeroes, which would drag
    a split deployment's CloudWatch averages down.
    """
    import json

    from portunus.grpc.server import register_audit_metrics, register_auth_metrics
    from portunus.metrics import MetricsAggregator

    class _Queue:
        submitted_total = published_total = dropped_total = 0
        build_failed_total = delivery_failed_total = 0
        skipped_unconfigured_total = sentinel_dropped_total = 0
        queued_bytes = 0

        def qsize(self) -> int:
            return 0

    class _Proc:
        active_stream_count = 0

    class _Cache:
        hits_total = stale_served_total = misses_total = coalesced_total = 0

    class _Auth:
        local_cache = _Cache()

    def _emitted(register) -> set[str]:
        metrics = MetricsAggregator(
            enabled=True, namespace="Portunus", service_name="p", role="all"
        )
        register(metrics)
        metrics.flush()
        doc = json.loads(capsys.readouterr().out.strip())
        return {m["Name"] for m in doc["_aws"]["CloudWatchMetrics"][0]["Metrics"]}

    auth_only = _emitted(lambda m: register_auth_metrics(m, _Auth()))  # type: ignore[arg-type]
    audit_only = _emitted(
        lambda m: register_audit_metrics(m, _Queue(), _Proc(), None)  # type: ignore[arg-type]
    )

    assert auth_only == {
        "AuthCacheL1Hit",
        "AuthCacheL1StaleServed",
        "AuthCacheL1Miss",
        "AuthCacheL1Coalesced",
    }
    assert auth_only.isdisjoint(audit_only)
    assert "PublishQueueDepth" in audit_only
