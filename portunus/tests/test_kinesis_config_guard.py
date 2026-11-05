"""Tests for the gRPC startup Kinesis audit-config fail-fast guard.

Because ``PublishService.build_*`` returns ``None`` (warning only) when a
stream is unset, a task with ``KINESIS_*`` env vars missing would serve while
silently dropping all audit records; the guard must refuse to start instead.
"""

from __future__ import annotations

import pytest

from portunus.config import GrpcConfig, KinesisConfig
from portunus.grpc.server import start_grpc_server

# The seven required streams, as their KINESIS_* env-var names.
_ALL_ENV_VARS = {
    "KINESIS_METADATA_STREAM",
    "KINESIS_REQUEST_HEADERS_STREAM",
    "KINESIS_REQUEST_BODY_STREAM",
    "KINESIS_REQUEST_TRAILERS_STREAM",
    "KINESIS_RESPONSE_HEADERS_STREAM",
    "KINESIS_RESPONSE_BODY_STREAM",
    "KINESIS_RESPONSE_TRAILERS_STREAM",
}


def _all_streams_set() -> KinesisConfig:
    """A KinesisConfig with every *required* stream set.

    ``ws_summary_stream_name`` left unset: it is not required.
    """
    return KinesisConfig(
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
    """Minimal stand-in: only ``put_records`` is wired by startup."""

    async def put_records(self, stream_name: str, records: list[bytes]) -> int:
        return 0


class TestMissingRequiredStreams:
    """Unit tests for ``KinesisConfig.missing_required_streams()``."""

    def test_all_unset_returns_all_env_vars(self):
        """All seven env vars are reported missing when none are configured."""
        assert set(KinesisConfig().missing_required_streams()) == _ALL_ENV_VARS

    def test_all_set_returns_empty(self):
        """Nothing is missing when every required stream is configured."""
        assert _all_streams_set().missing_required_streams() == []

    def test_single_unset_is_reported(self):
        """Only the unset stream's env var is reported."""
        kinesis = _all_streams_set().model_copy(
            update={"request_body_stream_name": None}
        )
        assert kinesis.missing_required_streams() == ["KINESIS_REQUEST_BODY_STREAM"]

    def test_empty_string_counts_as_missing(self):
        """An empty string is treated as unset (falsy)."""
        kinesis = _all_streams_set().model_copy(update={"metadata_stream_name": ""})
        assert "KINESIS_METADATA_STREAM" in kinesis.missing_required_streams()


class TestStartupFailFast:
    """``start_grpc_server`` must refuse to serve when audit is misconfigured."""

    @pytest.mark.asyncio
    async def test_all_streams_unset_refuses_to_start(self):
        """Every KINESIS_* unset -> startup raises before binding a port."""
        config = GrpcConfig(enabled=True, proxy_api_key="a-key-of-adequate-length")
        with pytest.raises(RuntimeError, match="Refusing to start"):
            await start_grpc_server(
                config=config,
                kinesis=KinesisConfig(),
                auth_service=_FakeAuthService(),  # type: ignore[arg-type]
                publish_service=_FakePublishService(),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_single_missing_stream_names_the_env_var(self):
        """A single missing required stream raises and names its env var."""
        kinesis = _all_streams_set().model_copy(update={"metadata_stream_name": None})
        config = GrpcConfig(enabled=True, proxy_api_key="a-key-of-adequate-length")
        with pytest.raises(RuntimeError, match="KINESIS_METADATA_STREAM"):
            await start_grpc_server(
                config=config,
                kinesis=kinesis,
                auth_service=_FakeAuthService(),  # type: ignore[arg-type]
                publish_service=_FakePublishService(),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_starts_when_all_required_streams_configured(self):
        """A fully-configured audit sink starts serving (runtime returned).

        ``ws_summary`` stays unset to confirm it does not gate startup.
        """
        config = GrpcConfig(
            enabled=True,
            proxy_api_key="a-key-of-adequate-length",
            # Ephemeral port distinct from the other startup tests.
            port=50053,
        )
        runtime = await start_grpc_server(
            config=config,
            kinesis=_all_streams_set(),
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
    async def test_disabled_server_skips_kinesis_guard(self):
        """``enabled=False`` returns None without tripping any startup guard.

        Guards must not fire on a non-serving server, even with every stream
        unset; default ``proxy_api_key=""`` also covers the proxy-key guard.
        """
        config = GrpcConfig(enabled=False)
        assert (
            await start_grpc_server(
                config=config,
                kinesis=KinesisConfig(),
                auth_service=_FakeAuthService(),  # type: ignore[arg-type]
                publish_service=_FakePublishService(),  # type: ignore[arg-type]
            )
            is None
        )
