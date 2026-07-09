"""Tests for the bounded signing path.

``sign_request_async`` must:

- run the blocking signer on the dedicated ``kms-sign`` executor, not the
  process-default ``asyncio.to_thread`` pool;
- cap concurrent signing requests with a semaphore (excess waits);
- shed waiters with ``SigningOverloadedError`` once the acquire timeout
  passes (so buffered 32 MiB bodies can't pile up unbounded);
- release the semaphore on both success and signer failure.
"""

import asyncio
import threading
from typing import Any

import pytest

from portunus.models import AwsCredentials, SigningKey
from portunus.services import signing_service
from portunus.services.signing_service import (
    SignableRequest,
    SigningOverloadedError,
    sign_request_async,
)

_HEADERS = {"Signature-Input": "sig1=()", "Signature": "sig1=:x:"}


@pytest.fixture
def signable_request() -> SignableRequest:
    return SignableRequest(
        type="anthropic",
        url="https://api.anthropic.com/v1/messages",  # type: ignore[arg-type]
        method="POST",
        content_type="application/json",
        content_digest="sha-256=:abc:",
    )


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey(
        provider_id="prov-1",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/abc",
    )


@pytest.fixture
def credentials() -> AwsCredentials:
    return AwsCredentials(
        access_key_id="AKIATEST123",
        secret_access_key="secretkey123",
        session_token="sessiontoken123",
    )


@pytest.fixture(autouse=True)
def _fresh_signing_runtime():
    """Isolate the module-level executor/semaphores between tests."""
    signing_service.reset_signing_runtime(wait=True)
    yield
    signing_service.reset_signing_runtime(wait=True)


def _patch_settings(monkeypatch, workers: int, max_concurrent: int, timeout: float):
    monkeypatch.setattr(
        signing_service,
        "_signing_settings",
        lambda: (workers, max_concurrent, timeout),
    )


class _BlockingSigner:
    """Sync signer that blocks until released, tracking peak concurrency."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls = 0
        self.thread_names: list[str] = []
        self.release = threading.Event()

    def __call__(self, req: Any, key: Any, api_key: Any, creds: Any) -> Any:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.thread_names.append(threading.current_thread().name)
        try:
            assert self.release.wait(timeout=10), "signer never released"
            return dict(_HEADERS)
        finally:
            with self._lock:
                self.active -= 1


async def _wait_for(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_concurrent_signing_is_capped(
    monkeypatch, signable_request, signing_key, credentials
):
    """6 concurrent signs against a cap of 2 never exceed 2 in flight."""
    _patch_settings(monkeypatch, workers=8, max_concurrent=2, timeout=30.0)
    signer = _BlockingSigner()

    tasks = [
        asyncio.ensure_future(
            sign_request_async(
                signable_request, signing_key, credentials.session_token or "",
                credentials, sign_fn=signer,
            )
        )
        for _ in range(6)
    ]
    # The first 2 enter the signer; the other 4 wait on the semaphore.
    await _wait_for(lambda: signer.active == 2)
    await asyncio.sleep(0.05)  # give excess tasks a chance to (wrongly) enter
    assert signer.active == 2
    assert signer.max_active == 2

    signer.release.set()
    results = await asyncio.gather(*tasks)
    assert all(r == _HEADERS for r in results)
    assert signer.calls == 6
    assert signer.max_active == 2, "concurrency cap was breached"


@pytest.mark.asyncio
async def test_excess_signing_sheds_cleanly_after_timeout(
    monkeypatch, signable_request, signing_key, credentials
):
    """A waiter past the acquire timeout is shed with SigningOverloadedError."""
    _patch_settings(monkeypatch, workers=4, max_concurrent=1, timeout=0.05)
    signer = _BlockingSigner()

    holder = asyncio.ensure_future(
        sign_request_async(
            signable_request, signing_key, "key", credentials, sign_fn=signer
        )
    )
    await _wait_for(lambda: signer.active == 1)

    with pytest.raises(SigningOverloadedError):
        await sign_request_async(
            signable_request, signing_key, "key", credentials, sign_fn=signer
        )
    # Shed request never reached the signer (its buffered body is freed).
    assert signer.calls == 1

    signer.release.set()
    assert await holder == _HEADERS


@pytest.mark.asyncio
async def test_signing_runs_on_dedicated_kms_executor(
    monkeypatch, signable_request, signing_key, credentials
):
    """The signer executes on the sized 'kms-sign' pool, not to_thread's."""
    _patch_settings(monkeypatch, workers=2, max_concurrent=2, timeout=1.0)
    signer = _BlockingSigner()
    signer.release.set()

    await sign_request_async(
        signable_request, signing_key, "key", credentials, sign_fn=signer
    )
    assert signer.thread_names, "signer never ran"
    assert all(name.startswith("kms-sign") for name in signer.thread_names)


@pytest.mark.asyncio
async def test_semaphore_released_after_signer_failure(
    monkeypatch, signable_request, signing_key, credentials
):
    """A signer exception frees the slot — the next request is not shed."""
    _patch_settings(monkeypatch, workers=2, max_concurrent=1, timeout=0.2)

    def failing_signer(req: Any, key: Any, api_key: Any, creds: Any) -> Any:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        await sign_request_async(
            signable_request, signing_key, "key", credentials, sign_fn=failing_signer
        )

    ok_signer = _BlockingSigner()
    ok_signer.release.set()
    result = await sign_request_async(
        signable_request, signing_key, "key", credentials, sign_fn=ok_signer
    )
    assert result == _HEADERS


@pytest.mark.asyncio
async def test_default_sign_fn_is_sign_request(
    monkeypatch, signable_request, signing_key, credentials
):
    """Without sign_fn the wrapper drives signing_service.sign_request."""
    _patch_settings(monkeypatch, workers=2, max_concurrent=2, timeout=1.0)
    seen: dict[str, Any] = {}

    def fake_sign_request(req: Any, key: Any, api_key: Any, creds: Any) -> Any:
        seen["args"] = (req, key, api_key, creds)
        return dict(_HEADERS)

    monkeypatch.setattr(signing_service, "sign_request", fake_sign_request)
    result = await sign_request_async(
        signable_request, signing_key, "the-key", credentials
    )
    assert result == _HEADERS
    assert seen["args"] == (signable_request, signing_key, "the-key", credentials)
