"""Tests for service-to-service authentication on Portunus endpoints."""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import portunus.app as app_module
from portunus.config import config
from portunus.services.service_auth import shared_secret_valid

SECRET = "test-shared-secret"
HEADER = "x-api-key"


@pytest.fixture
def client(monkeypatch):
    """TestClient with external side effects stubbed out."""

    async def fake_flush_all():
        return True

    async def fake_publish(*args, **kwargs):
        return True

    async def fake_health_check():
        return True

    monkeypatch.setattr(app_module.cache_service, "flush_all", fake_flush_all)
    monkeypatch.setattr(
        app_module.publish_service, "publish_request_headers", fake_publish
    )
    monkeypatch.setattr(app_module.state_service, "health_check", fake_health_check)
    return TestClient(app_module.portunus)


@pytest.fixture
def secret_configured(monkeypatch):
    """Configure a shared secret for the duration of a test."""
    monkeypatch.setattr(config.service_auth, "shared_secret", SECRET)
    monkeypatch.setattr(config.service_auth, "header", HEADER)


class TestSharedSecretValid:
    def test_no_secret_configured_denies_all(self, monkeypatch):
        monkeypatch.setattr(config.service_auth, "shared_secret", None)
        assert shared_secret_valid({}) is False
        assert shared_secret_valid({HEADER: "anything"}) is False

    def test_matching_secret(self, secret_configured):
        assert shared_secret_valid({HEADER: SECRET}) is True

    def test_missing_header(self, secret_configured):
        assert shared_secret_valid({}) is False

    def test_wrong_secret(self, secret_configured):
        assert shared_secret_valid({HEADER: "wrong"}) is False


class TestHttpEndpoints:
    def test_cache_flush_rejected_without_secret(self, client, secret_configured):
        response = client.post("/cache/flush")
        assert response.status_code == 401

    def test_cache_flush_rejected_with_wrong_secret(self, client, secret_configured):
        response = client.post("/cache/flush", headers={HEADER: "wrong"})
        assert response.status_code == 401

    def test_cache_flush_allowed_with_secret(self, client, secret_configured):
        response = client.post("/cache/flush", headers={HEADER: SECRET})
        assert response.status_code == 200

    def test_log_endpoint_rejected_without_secret(self, client, secret_configured):
        response = client.post(
            "/log/req-1/request/headers",
            json={"timestamp": 1700000000, "headers": {"host": "example.com"}},
        )
        assert response.status_code == 401

    def test_log_endpoint_allowed_with_secret(self, client, secret_configured):
        response = client.post(
            "/log/req-1/request/headers",
            json={"timestamp": 1700000000, "headers": {"host": "example.com"}},
            headers={HEADER: SECRET},
        )
        assert response.status_code == 200

    def test_authorise_rejected_without_secret(self, client, secret_configured):
        response = client.post("/authorise", json={"payload": "irrelevant"})
        assert response.status_code == 401

    def test_ping_open_without_secret(self, client, secret_configured):
        response = client.get("/ping")
        assert response.status_code == 200

    def test_no_secret_configured_denies_requests(self, client, monkeypatch):
        monkeypatch.setattr(config.service_auth, "shared_secret", None)
        response = client.post("/cache/flush", headers={HEADER: "anything"})
        assert response.status_code == 401


class TestStartup:
    def test_startup_fails_without_secret(self, monkeypatch):
        monkeypatch.setattr(config.service_auth, "shared_secret", None)
        with pytest.raises(RuntimeError, match="PORTUNUS_API_KEY must be set"):
            with TestClient(app_module.portunus):
                pass

    def test_startup_succeeds_with_secret(self, secret_configured):
        with TestClient(app_module.portunus):
            pass


class TestWebSocketRelay:
    def test_ws_rejected_without_secret(self, client, secret_configured):
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/v1/responses"):
                pass
        assert exc_info.value.code == 4001
