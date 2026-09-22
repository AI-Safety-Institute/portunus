"""Configured-off tracing leaves application coroutines independent of the SDK."""

import asyncio

import pytest

from portunus.services import xray_service


@pytest.mark.asyncio
async def test_disabled_tracing_runs_without_an_available_recorder(monkeypatch):
    monkeypatch.setattr(xray_service.config.aws, "xray_enabled", False)

    def unavailable(*args):
        raise RuntimeError("Synthetic recorder failure")

    monkeypatch.setattr(xray_service.xray_recorder, "capture_async", unavailable)

    @xray_service.capture_async("disabled")
    async def operation(value):
        if isinstance(value, BaseException):
            raise value
        return value + 1

    assert await operation(3) == 4
    with pytest.raises(ValueError, match="synthetic"):
        await operation(ValueError("synthetic"))
    with pytest.raises(asyncio.CancelledError):
        await operation(asyncio.CancelledError())


@pytest.mark.asyncio
async def test_enabled_tracing_keeps_sdk_instrumentation(monkeypatch):
    monkeypatch.setattr(xray_service.config.aws, "xray_enabled", True)
    captured = []

    def decorate(name):
        def apply(function):
            async def invoke(*args, **kwargs):
                captured.append(name)
                return await function(*args, **kwargs)

            return invoke

        return apply

    monkeypatch.setattr(xray_service.xray_recorder, "capture_async", decorate)

    @xray_service.capture_async("enabled")
    async def operation(value):
        return value + 1

    assert await operation(3) == 4
    assert captured == ["enabled"]
