"""Tests for the Redis API authentication response caching functionality."""

import hashlib
import json
import os
import sys
import uuid

import pytest
from conftest import dump_container_logs

# Add portunus to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))

# Now imports should work
from portunus.models import PrincipalInfo
from portunus.services.cache_service import CacheService
from portunus.services.state_service import StateService

# Global test instances to reuse across tests
_test_redis_client = None
_state_service = StateService()
_cache_service = CacheService(_state_service)
TARGET_HOST = "api.example.com"


@pytest.fixture(autouse=True)
def reset_redis_client():
    """Reset global Redis client between tests to prevent event loop issues.

    The global _test_redis_client caches a Redis connection for reuse, but when
    pytest creates a new event loop for each test, the cached client becomes
    attached to the old loop. This causes "Event loop is closed" errors.
    Resetting the client ensures each test gets a fresh connection on the current loop.
    """
    global _test_redis_client
    _test_redis_client = None
    yield


@pytest.fixture(autouse=True)
def log_on_failure(request):
    """Automatically dump container logs when a test fails."""
    yield
    if request.node.rep_setup.failed or request.node.rep_call.failed:
        print(f"\nTest failed: {request.node.name}, dumping container logs")
        dump_container_logs(request.node.name)


# Helper function to create Redis client
async def get_test_redis_client():
    """Get a Redis client for testing, creating one if needed."""
    global _test_redis_client

    # If we already have a working client, return it
    if _test_redis_client is not None:
        return _test_redis_client

    import redis.asyncio as aioredis

    # Set up Redis credentials from environment
    host = os.environ.get("REDIS_HOST", "localhost")
    port = int(os.environ.get("REDIS_PORT", 6379))
    password = os.environ.get("REDIS_PASSWORD", "redis_secure_password")

    print(
        f"Connecting to Redis at {host}:{port} with password length: "
        f"{len(password) if password else 0}"
    )

    # Create a new Redis client with the correct configuration
    client = aioredis.Redis(
        host=host,
        port=port,
        password=password,
        decode_responses=True,
        max_connections=10,
    )

    # Test the connection
    try:
        await client.ping()
        # If successful, store the client for reuse
        _test_redis_client = client
        print("Successfully connected to Redis")
        return client
    except Exception as e:
        print(f"Error connecting to Redis: {e}")
        # Try alternative connection parameters
        try:
            # Try the Redis container name instead of localhost
            client = aioredis.Redis(
                host="redis",  # Container name from docker-compose
                port=6379,
                password=password,
                decode_responses=True,
            )
            await client.ping()
            _test_redis_client = client
            print("Successfully connected to Redis using container name")
            return client
        except Exception as e2:
            print(f"Error connecting to Redis with alternative settings: {e2}")
            raise


@pytest.mark.asyncio
async def test_generate_cache_key():
    """Test cache key generation."""
    # Test with a simple string
    payload = "test-payload"
    expected_key = hashlib.sha256(f"{payload}\n{TARGET_HOST}".encode()).hexdigest()
    generated_key = _cache_service.generate_cache_key(payload, TARGET_HOST)
    assert generated_key == expected_key, "Cache key generation failed"
    assert _cache_service.generate_cache_key(payload, "api.other.example") != (
        generated_key
    ), "Cache key must depend on the target host"

    # Test with a JSON-like string
    payload = '{"credentials": {"access_key": "AKIA123", "secret_key": "SECRET"}, "secret_arn": "arn:aws:..."}'  # noqa: E501
    expected_key = hashlib.sha256(f"{payload}\n{TARGET_HOST}".encode()).hexdigest()
    generated_key = _cache_service.generate_cache_key(payload, TARGET_HOST)
    assert generated_key == expected_key, (
        "Cache key generation failed for complex payload"
    )


@pytest.mark.asyncio
async def test_cache_and_retrieve_auth_result(docker_setup, request):
    """A cached auth response round-trips through Redis as an AuthResult."""
    payload = f"test-payload-roundtrip-{uuid.uuid4()}"
    api_key = "sk-test-api-key-roundtrip"
    principal_info = PrincipalInfo(
        account_id="123456789012",
        principal="test-principal-roundtrip",
        session_name="test-session",
    )

    # Set up Redis connection
    test_client = await get_test_redis_client()
    original_state_redis_client = _state_service.redis_client
    _state_service.redis_client = test_client

    def cleanup():
        _state_service.redis_client = original_state_redis_client

    request.addfinalizer(cleanup)

    result = await _cache_service.cache_auth_response(
        payload, TARGET_HOST, api_key, principal_info
    )
    assert result is True, "Failed to cache auth response"

    cached_response = await _cache_service.get_cached_auth_result(payload, TARGET_HOST)

    assert cached_response is not None, "Failed to retrieve cached auth response"
    assert cached_response.api_key == api_key, "Retrieved API key doesn't match"
    assert cached_response.principal_info.account_id == principal_info.account_id
    assert cached_response.principal_info.principal == principal_info.principal


@pytest.mark.asyncio
async def test_cache_entry_with_legacy_signing_key_loads(docker_setup, request):
    """Entries written before request signing was removed still load.

    Those entries carry a populated signing_key field, which is now ignored.
    """
    payload = f"test-payload-legacy-signing-{uuid.uuid4()}"
    api_key = "sk-test-api-key-legacy-signing"
    principal_info = PrincipalInfo(
        account_id="123456789012",
        principal="test-principal-legacy-signing",
        session_name="test-session",
    )

    # Set up Redis connection
    test_client = await get_test_redis_client()
    original_state_redis_client = _state_service.redis_client
    _state_service.redis_client = test_client

    def cleanup():
        _state_service.redis_client = original_state_redis_client

    request.addfinalizer(cleanup)

    legacy_entry = {
        "api_key": api_key,
        "principal_info": principal_info.to_dict(),
        "signing_key": {
            "provider_id": "signingkey_test123",
            "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
        },
    }
    async with await get_test_redis_client() as client:
        await client.set(
            _cache_service.generate_cache_key(payload, TARGET_HOST),
            json.dumps(legacy_entry),
        )

    cached_response = await _cache_service.get_cached_auth_result(payload, TARGET_HOST)

    assert cached_response is not None, "Failed to retrieve cached auth response"
    assert cached_response.api_key == api_key, "Retrieved API key doesn't match"
    assert cached_response.principal_info.account_id == principal_info.account_id
    assert cached_response.principal_info.principal == principal_info.principal
