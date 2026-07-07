"""Tests for service-to-service authentication on Portunus endpoints."""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import portunus.app as app_module
from portunus.config import PortunusConfig, ServiceAuthConfig
from portunus.services.service_auth import ServiceAuth

# The app's ServiceAuth is parsed from the PORTUNUS_API_KEY set in conftest.py
SECRET = app_module.service_auth.secret
HEADER = app_module.service_auth.header


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


class TestFromConfig:
    def test_missing_secret_raises(self):
        config = PortunusConfig(service_auth=ServiceAuthConfig(shared_secret=None))
        with pytest.raises(RuntimeError, match="PORTUNUS_API_KEY must be set"):
            ServiceAuth.from_config(config)

    def test_empty_secret_raises(self):
        config = PortunusConfig(service_auth=ServiceAuthConfig(shared_secret=""))
        with pytest.raises(RuntimeError, match="PORTUNUS_API_KEY must be set"):
            ServiceAuth.from_config(config)

    def test_parses_secret_and_header(self):
        config = PortunusConfig(
            service_auth=ServiceAuthConfig(shared_secret="s3cret", header="x-custom")
        )
        auth = ServiceAuth.from_config(config)
        assert auth.secret == "s3cret"
        assert auth.header == "x-custom"


class TestValid:
    auth = ServiceAuth(secret="s3cret", header="x-custom-key")

    def test_matching_secret(self):
        assert self.auth.valid({"x-custom-key": "s3cret"}) is True

    def test_missing_header(self):
        assert self.auth.valid({}) is False

    def test_wrong_secret(self):
        assert self.auth.valid({"x-custom-key": "wrong"}) is False


class TestHttpEndpoints:
    def test_cache_flush_rejected_without_secret(self, client):
        response = client.post("/cache/flush")
        assert response.status_code == 401

    def test_cache_flush_rejected_with_wrong_secret(self, client):
        response = client.post("/cache/flush", headers={HEADER: "wrong"})
        assert response.status_code == 401

    def test_cache_flush_allowed_with_secret(self, client):
        response = client.post("/cache/flush", headers={HEADER: SECRET})
        assert response.status_code == 200

    def test_log_endpoint_rejected_without_secret(self, client):
        response = client.post(
            "/log/req-1/request/headers",
            json={"timestamp": 1700000000, "headers": {"host": "example.com"}},
        )
        assert response.status_code == 401

    def test_log_endpoint_allowed_with_secret(self, client):
        response = client.post(
            "/log/req-1/request/headers",
            json={"timestamp": 1700000000, "headers": {"host": "example.com"}},
            headers={HEADER: SECRET},
        )
        assert response.status_code == 200

    def test_authorise_rejected_without_secret(self, client):
        response = client.post("/authorise", json={"payload": "irrelevant"})
        assert response.status_code == 401

    def test_ping_open_without_secret(self, client):
        response = client.get("/ping")
        assert response.status_code == 200


class TestWebSocketRelay:
    def test_ws_rejected_without_secret(self, client):
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/v1/responses"):
                pass
        assert exc_info.value.code == 4001
