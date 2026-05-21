"""Shared pytest fixtures for portunus unit tests."""

import asyncio
import os
from typing import Awaitable
from unittest import mock

import aiobotocore.endpoint
import pytest

# Disable X-Ray SDK for tests
os.environ.setdefault("AWS_XRAY_SDK_ENABLED", "false")


@pytest.fixture
def moto_aiobotocore_patch():
    """Make moto's ``mock_aws`` work with aiobotocore.

    moto returns a sync ``AWSResponse`` whose ``content`` is bytes; aiobotocore
    >=2.21 awaits that attribute. Wrap it in a resolved Future.
    See aio-libs/aiobotocore#1300, getmoto/moto#8694.
    """
    original = aiobotocore.endpoint.convert_to_response_dict

    async def _wrapped(http_response, operation_model):
        if not isinstance(http_response._content, Awaitable):
            fut: asyncio.Future = asyncio.Future()
            fut.set_result(http_response.content)
            http_response._content = fut
        return await original(http_response, operation_model)

    with mock.patch("aiobotocore.endpoint.convert_to_response_dict", _wrapped):
        yield
