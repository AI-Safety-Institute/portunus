"""Shared pytest fixtures for portunus unit tests."""

import os

# Disable X-Ray SDK for tests
os.environ.setdefault("AWS_XRAY_SDK_ENABLED", "false")
