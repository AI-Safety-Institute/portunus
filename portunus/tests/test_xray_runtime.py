"""Enabled tracing must survive the native gRPC entrypoint and task concurrency."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("runner", ["native", "asyncio"])
def test_enabled_xray_startup_and_task_contexts(
    runner: str, unused_tcp_port: int
) -> None:
    environment = {
        **os.environ,
        "AWS_XRAY_SDK_ENABLED": "true",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "GRPC_ENABLED": "true",
        "GRPC_PORT": str(unused_tcp_port),
        "GRPC_PROXY_API_KEY": "local-tracing-runtime-key",
        "GRPC_HEALTH_CHECK_INTERVAL_SECONDS": "0",
        "GRPC_METRICS_INTERVAL_SECONDS": "0",
        "GRPC_GRACEFUL_SHUTDOWN_SECONDS": "1",
    }
    environment.update(
        {
            f"FIREHOSE_{part}_STREAM": "local-audit"
            for part in (
                "METADATA",
                "REQUEST_HEADERS",
                "REQUEST_BODY",
                "REQUEST_TRAILERS",
                "RESPONSE_HEADERS",
                "RESPONSE_BODY",
                "RESPONSE_TRAILERS",
            )
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("xray_runtime_probe.py")),
            runner,
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
