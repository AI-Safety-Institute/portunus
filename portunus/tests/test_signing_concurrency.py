"""Tests for the bounded signing path.

``sign_request_async`` runs the blocking signer on the dedicated ``kms-sign``
executor (not ``asyncio.to_thread``), caps concurrency with a semaphore, sheds
waiters with ``SigningOverloadedError`` past the acquire timeout (so buffered
bodies can't pile up), and releases the semaphore on success and failure.
"""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from portunus.config import config
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
    monkeypatch.setattr(config.signing, "kms_executor_workers", workers)
    monkeypatch.setattr(config.signing, "max_concurrent", max_concurrent)
    monkeypatch.setattr(config.signing, "acquire_timeout_s", timeout)


class _BlockingSigner:
    """Sync signer that blocks until released, tracking peak concurrency."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls = 0
        self.release = threading.Event()

    def __call__(self, req: Any, key: Any, api_key: Any, creds: Any) -> Any:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
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
                signable_request,
                signing_key,
                credentials.session_token or "",
                credentials,
                sign_fn=signer,
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
@pytest.mark.parametrize("signer_fails", [False, True])
async def test_cancelled_caller_holds_capacity_until_signer_finishes(
    monkeypatch, signable_request, signing_key, credentials, signer_fails
):
    _patch_settings(monkeypatch, workers=2, max_concurrent=1, timeout=0.05)
    signer = _BlockingSigner()

    def pending_signer(*args):
        result = signer(*args)
        if signer_fails:
            raise ValueError("Signing failed")
        return result

    holder = asyncio.create_task(
        sign_request_async(
            signable_request, signing_key, "key", credentials, sign_fn=pending_signer
        )
    )
    try:
        await _wait_for(lambda: signer.active == 1)
        holder.cancel()
        with pytest.raises(asyncio.CancelledError):
            await holder

        with pytest.raises(SigningOverloadedError):
            await sign_request_async(
                signable_request,
                signing_key,
                "key",
                credentials,
                sign_fn=lambda *_args: dict(_HEADERS),
            )

        signer.release.set()
        await _wait_for(lambda: signer.active == 0)
        assert (
            await sign_request_async(
                signable_request,
                signing_key,
                "key",
                credentials,
                sign_fn=lambda *_args: dict(_HEADERS),
            )
            == _HEADERS
        )
    finally:
        signer.release.set()
        holder.cancel()
        await asyncio.gather(holder, return_exceptions=True)


@pytest.mark.asyncio
async def test_pending_signing_leaves_default_executor_available(
    monkeypatch, signable_request, signing_key, credentials
):
    """A pending signing operation leaves the default executor available."""
    _patch_settings(monkeypatch, workers=2, max_concurrent=2, timeout=1.0)
    signer = _BlockingSigner()
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as default_executor:
        loop.set_default_executor(default_executor)
        holder = asyncio.create_task(
            sign_request_async(
                signable_request, signing_key, "key", credentials, sign_fn=signer
            )
        )
        try:
            await _wait_for(lambda: signer.active == 1)
            async with asyncio.timeout(1):
                assert await asyncio.to_thread(lambda: "default work") == "default work"
        finally:
            signer.release.set()
            async with asyncio.timeout(1):
                result = await holder
        assert result == _HEADERS


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
