"""Apply bounded publisher tuning at the gRPC server boundary."""

import asyncio
from collections.abc import Iterator

import pytest

from portunus.config import get_config
from portunus.grpc.server import start_grpc_server, stop_grpc_server
from portunus.services.publish_queue import PublishTask


@pytest.fixture
def grpc_environment(
    monkeypatch: pytest.MonkeyPatch, unused_tcp_port: int
) -> Iterator[None]:
    settings = {
        "AWS_DEFAULT_REGION": "us-east-1",
        "GRPC_ENABLED": "true",
        "GRPC_PORT": str(unused_tcp_port),
        "GRPC_PROXY_API_KEY": "local-publisher-tuning-key",
        "GRPC_HEALTH_CHECK_INTERVAL_SECONDS": "0",
        "METRICS_ENABLED": "false",
    }
    settings.update(
        {
            f"FIREHOSE_{component}_STREAM": "audit"
            for component in (
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
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    for name in (
        "GRPC_PUBLISH_WORKERS",
        "GRPC_PUBLISH_BATCH_SIZE",
        "GRPC_PUBLISH_COALESCE_MS",
    ):
        monkeypatch.delenv(name, raising=False)
    get_config.cache_clear()
    yield
    get_config.cache_clear()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GRPC_PUBLISH_WORKERS", "0"),
        ("GRPC_PUBLISH_WORKERS", "-1"),
        ("GRPC_PUBLISH_WORKERS", "65"),
        ("GRPC_PUBLISH_WORKERS", "invalid"),
        ("GRPC_PUBLISH_BATCH_SIZE", "0"),
        ("GRPC_PUBLISH_BATCH_SIZE", "3001"),
        ("GRPC_PUBLISH_BATCH_SIZE", "invalid"),
        ("GRPC_PUBLISH_COALESCE_MS", "-1"),
        ("GRPC_PUBLISH_COALESCE_MS", "101"),
        ("GRPC_PUBLISH_COALESCE_MS", "nan"),
        ("GRPC_PUBLISH_COALESCE_MS", "inf"),
        ("GRPC_PUBLISH_COALESCE_MS", "invalid"),
    ],
)
def test_invalid_publisher_environment_is_rejected(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv(name, value)
    get_config.cache_clear()
    try:
        with pytest.raises(ValueError):
            get_config()
    finally:
        get_config.cache_clear()


@pytest.mark.asyncio
@pytest.mark.parametrize(("workers", "batch_size"), [(1, 2), (2, 3)])
async def test_environment_limits_concurrent_batches(
    grpc_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    workers: int,
    batch_size: int,
) -> None:
    monkeypatch.setenv("GRPC_PUBLISH_WORKERS", str(workers))
    monkeypatch.setenv("GRPC_PUBLISH_BATCH_SIZE", str(batch_size))
    batches: list[list[bytes]] = []
    started = asyncio.Event()
    release = asyncio.Event()

    class Publisher:
        async def put_record_batch(self, stream: str, records: list[bytes]) -> int:
            batches.append(list(records))
            if len(batches) == workers:
                started.set()
            await release.wait()
            return 0

    config = get_config()
    runtime = await start_grpc_server(
        config=config.grpc,
        firehose=config.firehose,
        auth_service=object(),  # type: ignore[arg-type]
        publish_service=Publisher(),  # type: ignore[arg-type]
    )
    assert runtime is not None
    records = [str(index).encode() for index in range(workers * batch_size + 1)]
    try:
        for record in records:

            def build(data: bytes = record) -> tuple[str, bytes]:
                return "audit", data

            assert runtime.publish_queue.submit_droppable(
                PublishTask(build=build, label="body")
            )
        await asyncio.wait_for(started.wait(), timeout=2)
        assert len(batches) == workers
        assert all(len(batch) == batch_size for batch in batches)
    finally:
        release.set()
        await stop_grpc_server(runtime, grace_seconds=2)
    assert sorted(item for batch in batches for item in batch) == sorted(records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("coalesce_ms", "expected_sizes"), [(None, [1, 1, 1]), (20, [1, 2])]
)
async def test_coalescing_wait_is_opt_in(
    grpc_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    coalesce_ms: int | None,
    expected_sizes: list[int],
) -> None:
    monkeypatch.setenv("GRPC_PUBLISH_WORKERS", "1")
    if coalesce_ms is not None:
        monkeypatch.setenv("GRPC_PUBLISH_COALESCE_MS", str(coalesce_ms))
    batches: list[list[bytes]] = []
    first_sent = asyncio.Event()
    delivered = asyncio.Event()

    class Publisher:
        async def put_record_batch(self, stream: str, records: list[bytes]) -> int:
            batches.append(list(records))
            first_sent.set()
            if sum(map(len, batches)) == 3:
                delivered.set()
            return 0

    config = get_config()
    runtime = await start_grpc_server(
        config=config.grpc,
        firehose=config.firehose,
        auth_service=object(),  # type: ignore[arg-type]
        publish_service=Publisher(),  # type: ignore[arg-type]
    )
    assert runtime is not None
    try:
        assert runtime.publish_queue.submit_droppable(
            PublishTask(build=lambda: ("audit", b"first"), label="body")
        )
        await asyncio.wait_for(first_sent.wait(), timeout=2)
        assert runtime.publish_queue.submit_droppable(
            PublishTask(build=lambda: ("audit", b"second"), label="body")
        )
        await asyncio.sleep(0)
        assert runtime.publish_queue.submit_droppable(
            PublishTask(build=lambda: ("audit", b"third"), label="body")
        )
        await asyncio.wait_for(delivered.wait(), timeout=2)
        assert [len(batch) for batch in batches] == expected_sizes
        assert [item for batch in batches for item in batch] == [
            b"first",
            b"second",
            b"third",
        ]
    finally:
        await stop_grpc_server(runtime, grace_seconds=2)
