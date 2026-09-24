"""Exercise proxy startup and shutdown through the built container entrypoint."""

import os
import socket
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import yaml

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def entrypoint_image():
    supplied = os.environ.get("PORTUNUS_TEST_PROXY_IMAGE")
    if supplied:
        yield supplied
        return
    name = f"portunus-entrypoint-test:{uuid.uuid4().hex}"
    subprocess.run(["docker", "build", "-t", name, "proxy"], check=True)
    try:
        yield name
    finally:
        subprocess.run(["docker", "image", "rm", name], check=True)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@dataclass
class Proxy:
    name: str
    listen_port: int
    admin_port: int

    def wait_for_ping(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                response = requests.get(
                    f"http://127.0.0.1:{self.listen_port}/ping", timeout=1
                )
                if response.status_code == 200:
                    return
            except requests.ConnectionError:
                pass
            time.sleep(0.05)
        pytest.fail("Proxy did not answer its liveness endpoint")


@contextmanager
def running_proxy(image, overrides, *, command=()):
    proxy = Proxy(f"portunus-entrypoint-{uuid.uuid4().hex}", free_port(), free_port())
    environment = {
        "PORTUNUS_API_KEY": "local-integration-proxy-key",
        "LISTEN_PORT": str(proxy.listen_port),
        "ADMIN_PORT": str(proxy.admin_port),
        "TARGET_HOST": "127.0.0.1",
        "TARGET_PORT": str(free_port()),
        "PORTUNUS_GRPC_PORT": str(free_port()),
        "TARGET_HOST_HTTP2_OPTIONS": "{}",
        "TARGET_HOST_TRANSPORT_SOCKET": "null",
        "WS_TARGET_HOST_TRANSPORT_SOCKET": "null",
        "DOWNSTREAM_TLS_TRANSPORT_SOCKET": "null",
        "ENVOY_LOG_LEVEL": "error",
        "DRAIN_TIME_S": "1",
    }
    environment.update(overrides)
    args = ["docker", "run", "-d", "--network", "host", "--name", proxy.name]
    for key, value in environment.items():
        args.extend(["-e", f"{key}={value}"])
    args.extend([image, *command])
    subprocess.run(args, check=True, capture_output=True)
    try:
        yield proxy
    finally:
        subprocess.run(
            ["docker", "rm", "-f", proxy.name], check=True, capture_output=True
        )


@pytest.mark.parametrize(
    ("key", "optional"), [("", "false"), ("short", "false"), ("short", "true")]
)
def test_invalid_proxy_identity_prevents_startup(entrypoint_image, key, optional):
    with running_proxy(
        entrypoint_image,
        {"PORTUNUS_API_KEY": key, "PORTUNUS_API_KEY_OPTIONAL": optional},
    ) as proxy:
        result = subprocess.run(
            ["docker", "wait", proxy.name], capture_output=True, text=True, timeout=8
        )
        assert result.stdout.strip() == "1"


@pytest.mark.parametrize(
    ("key", "optional"),
    [("local-integration-proxy-key", "false"), ("", "true")],
)
def test_valid_identity_or_explicit_local_opt_out_starts_proxy(
    entrypoint_image, key, optional
):
    with running_proxy(
        entrypoint_image,
        {"PORTUNUS_API_KEY": key, "PORTUNUS_API_KEY_OPTIONAL": optional},
    ) as proxy:
        proxy.wait_for_ping()


@pytest.mark.parametrize(("configured", "expected"), [(None, 1), ("2", 2)])
def test_proxy_uses_the_configured_worker_count(entrypoint_image, configured, expected):
    overrides = {} if configured is None else {"ENVOY_CONCURRENCY": configured}
    with running_proxy(entrypoint_image, overrides) as proxy:
        proxy.wait_for_ping()
        response = requests.get(
            f"http://127.0.0.1:{proxy.admin_port}/server_info", timeout=2
        )
        response.raise_for_status()
        assert response.json()["command_line_options"]["concurrency"] == expected


@pytest.mark.parametrize("workers", ["0", "00", "-1", "1.5", "2 --disable-hot-restart"])
def test_invalid_worker_count_prevents_startup(entrypoint_image, workers):
    with running_proxy(entrypoint_image, {"ENVOY_CONCURRENCY": workers}) as proxy:
        result = subprocess.run(
            ["docker", "wait", proxy.name], capture_output=True, text=True, timeout=8
        )
        assert result.stdout.strip() == "1"


@pytest.mark.parametrize("request_limit", [None, 2048])
def test_both_upstreams_publish_configured_request_capacity(
    entrypoint_image, request_limit
):
    overrides = {}
    if request_limit is not None:
        overrides = {
            "TARGET_MAX_REQUESTS": str(request_limit),
            "TARGET_MAX_PENDING_REQUESTS": "7",
        }
    with running_proxy(entrypoint_image, overrides) as proxy:
        proxy.wait_for_ping()
        response = requests.get(
            f"http://127.0.0.1:{proxy.admin_port}/stats?format=json", timeout=2
        )
        response.raise_for_status()
        stats = {
            item["name"]: item["value"]
            for item in response.json()["stats"]
            if "name" in item
        }
        for cluster in ("127.0.0.1", "ws_upstream"):
            prefix = f"cluster.{cluster}.circuit_breakers.default."
            assert stats[prefix + "remaining_rq"] == (request_limit or 1024)
            assert stats[prefix + "remaining_pending"] == (
                7 if request_limit is not None else 1024
            )


def test_shutdown_remains_bounded_when_admin_stops_responding(entrypoint_image):
    requested = threading.Event()
    release = threading.Event()

    class SlowAdmin(BaseHTTPRequestHandler):
        def do_POST(self):
            requested.set()
            release.wait(timeout=10)
            self.send_response(503)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowAdmin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Replace only the external Envoy process; the real shell entrypoint
        # talks to a slow local admin peer and must terminate its child.
        command = (
            "sh",
            "-c",
            'envoy() { if [ "$1" = --version ]; then command envoy --version; '
            "else exec sleep 3600; fi; }; . /envoy/entrypoint.sh",
        )
        with running_proxy(
            entrypoint_image, {"ADMIN_PORT": str(server.server_port)}, command=command
        ) as proxy:
            time.sleep(1)
            subprocess.run(
                ["docker", "kill", "--signal=TERM", proxy.name],
                check=True,
                capture_output=True,
            )
            assert requested.wait(timeout=3)
            result = subprocess.run(
                ["docker", "wait", proxy.name],
                capture_output=True,
                text=True,
                timeout=4,
            )
            assert result.stdout.strip() == "143"
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("audit_port", [None, "19001"])
def test_audit_listener_can_be_routed_separately(entrypoint_image, audit_port):
    overrides = {"PORTUNUS_GRPC_PORT": "19000"}
    if audit_port is not None:
        overrides["PORTUNUS_AUDIT_GRPC_PORT"] = audit_port
    with running_proxy(entrypoint_image, overrides) as proxy:
        proxy.wait_for_ping()
        rendered = subprocess.run(
            ["docker", "exec", proxy.name, "cat", "/envoy/envoy_subst.yaml"],
            check=True,
            capture_output=True,
            text=True,
        )
        clusters = yaml.safe_load(rendered.stdout)["static_resources"]["clusters"]
        ports = {
            cluster["name"]: cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][
                0
            ]["endpoint"]["address"]["socket_address"]["port_value"]
            for cluster in clusters
            if cluster["name"] in ("portunus_grpc_cluster", "portunus_extproc_cluster")
        }
        assert ports["portunus_grpc_cluster"] == 19000
        assert ports["portunus_extproc_cluster"] == int(audit_port or "19000")
