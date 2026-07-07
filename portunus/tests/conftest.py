"""Shared pytest fixtures for portunus unit tests."""

import asyncio
import os

# Disable X-Ray SDK for tests
os.environ.setdefault("AWS_XRAY_SDK_ENABLED", "false")

# Service endpoints require the proxy shared secret; hardcode one for tests
# (must be set before portunus.config is imported)
os.environ.setdefault("PORTUNUS_API_KEY", "test-shared-secret")

# aws_xray_sdk's AsyncContext calls asyncio.get_event_loop() when the recorder
# is configured (at portunus.app import). On Python >= 3.14 that raises if no
# event loop exists in the main thread, so provide one for test collection.
asyncio.set_event_loop(asyncio.new_event_loop())
