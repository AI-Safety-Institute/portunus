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
            metrics_interval_seconds=0,
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
