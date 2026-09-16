"""Exercise signing SDK retries and process exit against a finite local peer."""

import os
import signal
import subprocess
import sys
import threading
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from portunus.config import get_config
from portunus.models import AwsCredentials, SigningKey
from portunus.services import signing_service
from portunus.services.signing_service import SignableRequest, sign_request


@dataclass
class LocalKMS:
    url: str = ""
    calls: list[bytes] = field(default_factory=list)
    received: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)


@contextmanager
def kms_endpoint(*, stalled=False):
    endpoint = LocalKMS()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            endpoint.calls.append(
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
            )
            endpoint.received.set()
            if stalled:
                endpoint.release.wait(timeout=10)
            body = b'{"__type":"KMSInternalException","message":"temporary failure"}'
            with suppress(BrokenPipeError, ConnectionResetError):
                self.send_response(500)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    endpoint.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield endpoint
    finally:
        endpoint.release.set()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("attempts", [1, 2])
def test_transient_kms_errors_stop_at_configured_attempt_limit(monkeypatch, attempts):
    with kms_endpoint() as endpoint:
        monkeypatch.setenv("AWS_ENDPOINT_URL", endpoint.url)
        monkeypatch.setenv("AWS_MAX_ATTEMPTS", "4")
        monkeypatch.setenv("SIGNING_KMS_MAX_ATTEMPTS", str(attempts))
        get_config.cache_clear()
        monkeypatch.setattr(signing_service, "config", get_config())
        get_config.cache_clear()
        with pytest.raises(ClientError):
            sign_request(
                SignableRequest(
                    type="anthropic",
                    url="https://api.example.com/messages",  # type: ignore[arg-type]
                    method="POST",
                    content_type="application/json",
                    content_digest="sha-256=:abc:",
                ),
                SigningKey(
                    provider_id="test-provider",
                    kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
                ),
                "local-provider-key",
                AwsCredentials(
                    access_key_id="local-access-key",
                    secret_access_key="local-secret-key",
                ),
            )
        assert len(endpoint.calls) == attempts


def test_process_exits_after_cancelled_signing_with_stalled_kms():
    child_program = """
import asyncio
import signal

from portunus.models import AwsCredentials, SigningKey
from portunus.services.signing_service import (
    SignableRequest, reset_signing_runtime, sign_request_async,
)

async def main():
    stop = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    task = asyncio.create_task(sign_request_async(
        SignableRequest(type="anthropic", url="https://api.example.com/messages",
                        method="POST", content_type="application/json",
                        content_digest="sha-256=:abc:"),
        SigningKey(provider_id="test-provider",
                   kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test"),
        "local-provider-key",
        AwsCredentials(access_key_id="local-access-key",
                       secret_access_key="local-secret-key"),
    ))
    await stop.wait()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    reset_signing_runtime(wait=False)

asyncio.run(main())
"""
    with kms_endpoint(stalled=True) as endpoint:
        environment = {
            **os.environ,
            "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            "AWS_XRAY_SDK_ENABLED": "false",
            "AWS_ENDPOINT_URL": endpoint.url,
            "AWS_MAX_ATTEMPTS": "4",
            "SIGNING_KMS_CONNECT_TIMEOUT_S": "0.1",
            "SIGNING_KMS_READ_TIMEOUT_S": "0.1",
            "SIGNING_KMS_MAX_ATTEMPTS": "2",
        }
        child = subprocess.Popen(
            [sys.executable, "-c", child_program],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert endpoint.received.wait(timeout=10), "Signer did not reach local KMS"
            child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=4)
            assert child.returncode == 0, (stdout, stderr)
            assert len(endpoint.calls) == 2
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
