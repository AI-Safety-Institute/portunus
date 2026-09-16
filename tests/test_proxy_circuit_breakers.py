"""Exercise HTTP/2 request admission through the real proxy image (Linux/Docker)."""

import json
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socket import socket
from textwrap import indent

import pytest
import requests
import yaml


@pytest.fixture(scope="module")
def proxy_image():
    name = f"portunus-breaker-test:{uuid.uuid4().hex}"
    subprocess.run(["docker", "build", "-t", name, "proxy"], check=True)
    try:
        yield name
    finally:
        subprocess.run(["docker", "image", "rm", name], check=True)


@contextmanager
def mock_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def free_port():
    with socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_until(predicate):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except requests.ConnectionError:
            pass
        time.sleep(0.05)
    pytest.fail("Timed out waiting for the proxy")


class Backend(BaseHTTPRequestHandler):
    """Authorize dummy credentials and acknowledge audit writes."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps(
            {"api_key": "dummy-upstream-key", "request_id": uuid.uuid4().hex}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def http2_origin(h2_port, origin_port):
    """Bridge h2c to the stdlib HTTP/1 origin with an extra test-only listener."""
    return yaml.safe_load(f"""
listeners:
  - name: test_h2_origin
    address:
      socket_address: {{address: 127.0.0.1, port_value: {h2_port}}}
    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: test_h2_origin
              codec_type: HTTP2
              route_config:
                virtual_hosts:
                  - name: origin
                    domains: ["*"]
                    routes:
                      - match: {{prefix: /}}
                        route: {{cluster: test_origin, timeout: 0s}}
              http_filters:
                - name: envoy.filters.http.router
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
clusters:
  - name: test_origin
    connect_timeout: 1s
    load_assignment:
      cluster_name: test_origin
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address: {{address: 127.0.0.1, port_value: {origin_port}}}
""")  # noqa: E501


@pytest.mark.slow
@pytest.mark.parametrize("request_limit", [None, 2, 4])
def test_http2_request_limit(proxy_image, tmp_path, request_limit):
    """A third stream over one connection overflows at two, succeeds at four."""
    release = threading.Event()

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            release.wait(timeout=30)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    with mock_server(Backend) as backend_port, mock_server(Origin) as origin_port:
        listen_port, admin_port, h2_port = free_port(), free_port(), free_port()
        # Preserve template quoting: YAML round-tripping before envsubst can
        # turn quoted header placeholders into numbers/booleans on rendering.
        config = Path("proxy/envoy.yaml").read_text()
        origin = http2_origin(h2_port, origin_port)
        config = config.replace(
            "  clusters:\n",
            indent(yaml.safe_dump(origin["listeners"]), "  ") + "  clusters:\n",
        )
        config += indent(yaml.safe_dump(origin["clusters"]), "  ")
        config_file = tmp_path / "envoy.yaml"
        config_file.write_text(config)
        env = {
            "LISTEN_PORT": str(listen_port),
            "ADMIN_PORT": str(admin_port),
            "TARGET_HOST": "127.0.0.1",
            "TARGET_PORT": str(h2_port),
            "TARGET_HOST_USE_TLS": "false",
            "TARGET_HOST_TRANSPORT_SOCKET": "null",
            "DOWNSTREAM_TLS_TRANSPORT_SOCKET": "null",
            "PORTUNUS_HOST": "localhost",
            "PORTUNUS_PORT": str(backend_port),
            "PORTUNUS_TRANSPORT_SOCKET": "null",
            "PORTUNUS_API_KEY": "dummy-backend-key",
            "API_KEY_HEADER": "authorization",
            "API_KEY_PREFIX": "Bearer ",
            "AWS_XRAY_DAEMON_ADDRESS": "127.0.0.1",
            "ENVOY_LOG_LEVEL": "warn",
        }
        if request_limit is not None:
            env["TARGET_MAX_REQUESTS"] = str(request_limit)
            env["TARGET_MAX_PENDING_REQUESTS"] = "7"
        name = f"portunus-breaker-test-{uuid.uuid4().hex}"
        command = ["docker", "run", "-d", "--network", "host", "--name", name]
        for key, value in env.items():
            command.extend(["-e", f"{key}={value}"])
        command.extend(
            [
                "-v",
                f"{config_file}:/envoy/envoy.yaml:ro",
                proxy_image,
                "/bin/sh",
                "-c",
                # One worker makes boundary assertions deterministic. The real
                # entrypoint still supplies every environment default/render.
                "ENVOY_BIN=$(command -v envoy); "
                'envoy() { "$ENVOY_BIN" "$@" --concurrency 1; }; '
                ". /envoy/entrypoint.sh",
            ]
        )
        subprocess.run(command, check=True, capture_output=True)
        admin = f"http://127.0.0.1:{admin_port}"

        def stats():
            data = requests.get(f"{admin}/stats?format=json", timeout=2).json()
            return {
                item["name"]: item["value"] for item in data["stats"] if "name" in item
            }

        def active():
            return stats()["cluster.127.0.0.1.upstream_rq_active"]

        def request():
            return requests.get(
                f"http://127.0.0.1:{listen_port}/slow",
                headers={"Authorization": "Bearer dummy-payload"},
                timeout=30,
            )

        try:
            wait_until(lambda: requests.get(f"{admin}/ready", timeout=2).ok)
            prefix = "cluster.127.0.0.1.circuit_breakers.default."
            assert stats()[prefix + "remaining_rq"] == (request_limit or 1024)
            assert stats()[prefix + "remaining_pending"] == (
                7 if request_limit is not None else 1024
            )
            with ThreadPoolExecutor(max_workers=3) as pool:
                try:
                    first = pool.submit(request)
                    wait_until(lambda: active() == 1)
                    second = pool.submit(request)
                    wait_until(lambda: active() == 2)
                    third = pool.submit(request)
                    if request_limit == 2:
                        assert third.result(timeout=5).status_code == 503
                        assert active() == 2
                        assert stats()[prefix + "remaining_rq"] == 0
                    else:
                        wait_until(lambda: active() == 3)
                    assert stats()["cluster.127.0.0.1.upstream_cx_active"] == 1
                finally:
                    release.set()
                assert first.result(timeout=5).status_code == 200
                assert second.result(timeout=5).status_code == 200
                if request_limit != 2:
                    assert third.result(timeout=5).status_code == 200
            wait_until(lambda: active() == 0)
            if request_limit == 2:

                def overflow_logged():
                    logs = subprocess.check_output(
                        ["docker", "logs", name], text=True, stderr=subprocess.STDOUT
                    )
                    entries = [
                        json.loads(line)
                        for line in logs.splitlines()
                        if line.startswith("{")
                    ]
                    return any(
                        int(entry["response_code"]) == 503
                        and "UO" in entry["response_flags"]
                        and "overflow" in entry["response_code_details"]
                        for entry in entries
                    )

                wait_until(overflow_logged)
        finally:
            release.set()
            subprocess.run(["docker", "logs", name], check=True)
            subprocess.run(["docker", "rm", "-f", name], check=True)
