"""The publisher defaults are the load-tested settings (1 worker, 3000, 5 ms)."""

import pytest

from portunus.config import GrpcConfig, get_config


def test_field_defaults_are_the_load_tested_settings():
    grpc = GrpcConfig()
    assert grpc.publish_workers == 1
    assert grpc.publish_batch_size == 3000
    assert grpc.publish_coalesce_ms == 5.0


def test_environment_defaults_match_the_field_defaults(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in (
        "GRPC_PUBLISH_WORKERS",
        "GRPC_PUBLISH_BATCH_SIZE",
        "GRPC_PUBLISH_COALESCE_MS",
    ):
        monkeypatch.delenv(name, raising=False)
    get_config.cache_clear()
    try:
        grpc = get_config().grpc
    finally:
        get_config.cache_clear()
    assert (grpc.publish_workers, grpc.publish_batch_size) == (1, 3000)
    assert grpc.publish_coalesce_ms == pytest.approx(5.0)
