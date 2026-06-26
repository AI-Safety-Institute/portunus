"""Tests for the Firehose audit-config fail-fast guard and observable drops.

Covers finding F2 from the Kinesis -> Firehose migration (#22): a task whose
audit sink is misconfigured (e.g. still carrying the pre-migration ``KINESIS_*``
env vars, so every ``FIREHOSE_*`` is unset) used to silently drop 100% of audit
records while returning HTTP 200. These tests assert the two fixes:

1. A missing required Firehose stream fails startup (``lifespan`` raises) and
   readiness (``/ping`` returns 503), so a misconfigured instance never serves.
2. A runtime publish drop/failure is observable (counter + alarmable log) and
   non-blocking (still HTTP 200) -- not a silent 200-with-no-record.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from portunus import app as app_module
from portunus.app import lifespan, portunus
from portunus.config import config

_STREAM_FIELDS = (
    "metadata_stream_name",
    "request_headers_stream_name",
    "request_body_stream_name",
    "request_trailers_stream_name",
    "response_headers_stream_name",
    "response_body_stream_name",
    "response_trailers_stream_name",
)

_ALL_ENV_VARS = {
    "FIREHOSE_METADATA_STREAM",
    "FIREHOSE_REQUEST_HEADERS_STREAM",
    "FIREHOSE_REQUEST_BODY_STREAM",
    "FIREHOSE_REQUEST_TRAILERS_STREAM",
    "FIREHOSE_RESPONSE_HEADERS_STREAM",
    "FIREHOSE_RESPONSE_BODY_STREAM",
    "FIREHOSE_RESPONSE_TRAILERS_STREAM",
}


def _set_all_streams(monkeypatch, value):
    """Set every Firehose stream name on the shared config singleton."""
    for field in _STREAM_FIELDS:
        monkeypatch.setattr(config.firehose, field, value)


@pytest.fixture(autouse=True)
def reset_audit_counter():
    """Keep the module-level audit-failure counter isolated per test."""
    app_module.audit_publish_failures.clear()
    yield
    app_module.audit_publish_failures.clear()


@pytest.fixture
def mock_xray():
    """Provide a deterministic X-Ray segment with a fixed trace id."""
    mock_segment = MagicMock()
    mock_segment.trace_id = "test-trace-id"
    with patch("portunus.app.xray_service") as mock:
        mock.recorder.current_segment.return_value = mock_segment
        yield mock


@pytest_asyncio.fixture
async def http_client():
    """An ASGI client for the app (does not run lifespan startup/shutdown)."""
    async with AsyncClient(
        transport=ASGITransport(app=portunus), base_url="http://test"
    ) as client:
        yield client


class TestMissingRequiredStreams:
    """Unit tests for FirehoseConfig.missing_required_streams()."""

    def test_all_unset_returns_all_env_vars(self, monkeypatch):
        """All seven env vars are reported missing when none are configured."""
        _set_all_streams(monkeypatch, None)
        assert set(config.firehose.missing_required_streams()) == _ALL_ENV_VARS

    def test_all_set_returns_empty(self, monkeypatch):
        """Nothing is missing when every stream is configured."""
        _set_all_streams(monkeypatch, "a-stream")
        assert config.firehose.missing_required_streams() == []

    def test_single_unset_is_reported(self, monkeypatch):
        """Only the unset stream's env var is reported."""
        _set_all_streams(monkeypatch, "a-stream")
        monkeypatch.setattr(config.firehose, "request_body_stream_name", None)
        assert config.firehose.missing_required_streams() == [
            "FIREHOSE_REQUEST_BODY_STREAM"
        ]

    def test_empty_string_counts_as_missing(self, monkeypatch):
        """An empty string is treated as unset (falsy)."""
        _set_all_streams(monkeypatch, "a-stream")
        monkeypatch.setattr(config.firehose, "metadata_stream_name", "")
        assert "FIREHOSE_METADATA_STREAM" in config.firehose.missing_required_streams()


class TestLifespanFailFast:
    """The app must refuse to start when audit publishing is misconfigured."""

    @pytest.mark.asyncio
    async def test_raises_when_required_stream_missing(self, monkeypatch):
        """A missing required stream makes startup raise before serving."""
        _set_all_streams(monkeypatch, "a-stream")
        monkeypatch.setattr(config.firehose, "metadata_stream_name", None)

        with pytest.raises(RuntimeError) as exc_info:
            async with lifespan(portunus):
                pass  # pragma: no cover - startup should never complete

        message = str(exc_info.value)
        assert "Refusing to start" in message
        assert "FIREHOSE_METADATA_STREAM" in message

    @pytest.mark.asyncio
    async def test_does_not_raise_when_all_streams_configured(self, monkeypatch):
        """Startup proceeds (no config error) when every stream is set."""
        _set_all_streams(monkeypatch, "a-stream")
        # Stub queue lifecycle so the test exercises only the config guard.
        with (
            patch("portunus.app.start_log_queue", AsyncMock()),
            patch("portunus.app.stop_log_queue", AsyncMock()),
            patch.object(app_module.state_service, "close_redis_client", AsyncMock()),
        ):
            async with lifespan(portunus):
                pass


class TestPingReadiness:
    """/ping must fail readiness when required streams are unset."""

    @pytest.mark.asyncio
    async def test_ping_unhealthy_when_streams_missing(self, monkeypatch, http_client):
        """Misconfigured audit sink -> 503 unhealthy, even if Redis is up."""
        _set_all_streams(monkeypatch, None)
        with patch.object(
            app_module.state_service, "health_check", AsyncMock(return_value=True)
        ):
            resp = await http_client.get("/ping")

        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "unhealthy"
        assert body["firehose"] == "FAIL"

    @pytest.mark.asyncio
    async def test_ping_healthy_when_streams_configured(self, monkeypatch, http_client):
        """Configured audit sink -> 200 healthy with firehose OK."""
        _set_all_streams(monkeypatch, "a-stream")
        with patch.object(
            app_module.state_service, "health_check", AsyncMock(return_value=True)
        ):
            resp = await http_client.get("/ping")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["firehose"] == "OK"


class TestAuditDropObservable:
    """Runtime drops must be observable + non-blocking, not silent 200s."""

    @pytest.mark.asyncio
    async def test_publish_false_is_observable_not_silent(
        self, mock_xray, http_client, caplog
    ):
        """A publish returning False (unset stream) is counted + logged."""
        with patch.object(
            app_module.publish_service,
            "publish_request_headers",
            AsyncMock(return_value=False),
        ):
            with caplog.at_level(logging.CRITICAL, logger="api.access"):
                resp = await http_client.post(
                    "/log/req-h1/request/headers",
                    json={"headers": {"authorization": "c2VjcmV0"}, "timestamp": 0},
                )

        # Non-blocking: audit must never 5xx the customer request...
        assert resp.status_code == 200
        # ...but the drop is NOT silent: counter incremented + alarmable log.
        assert (
            app_module.audit_publish_failures["request_headers:stream_unconfigured"]
            == 1
        )
        assert "AUDIT_PUBLISH_DROPPED" in caplog.text

    @pytest.mark.asyncio
    async def test_publish_exception_is_observable_and_non_blocking(
        self, mock_xray, http_client, caplog
    ):
        """A transient publish failure is counted + logged but does not 5xx."""
        with patch.object(
            app_module.publish_service,
            "publish_request_headers",
            AsyncMock(side_effect=RuntimeError("firehose unavailable")),
        ):
            with caplog.at_level(logging.CRITICAL, logger="api.access"):
                resp = await http_client.post(
                    "/log/req-h1/request/headers",
                    json={"headers": {"authorization": "c2VjcmV0"}, "timestamp": 0},
                )

        assert resp.status_code == 200
        assert app_module.audit_publish_failures["request_headers:publish_error"] == 1
        assert "AUDIT_PUBLISH_DROPPED" in caplog.text
