"""Tests for the Redis API authentication response caching functionality."""

import json
import os
import sys
import uuid

import pytest
import redis.asyncio as aioredis
from conftest import dump_container_logs

# Add portunus to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))

# Now imports should work
from portunus.models import AuthResult, PrincipalInfo  # noqa: E402
from portunus.services.cache_service import CacheService  # noqa: E402
from portunus.services.state_service import StateService  # noqa: E402

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
    """Cache-key contract: determinism, host and payload sensitivity.

    A cached result is only reused for the host it was authorised for. Exact
    construction is
    unit-tested in portunus/tests/test_cache_key.py.
    """
    payload = "test-payload"
    target_host = "api.example.com"

    # Deterministic + Redis-safe (64-char sha256 hex).
    key_no_host = _cache_service.generate_cache_key(payload, None)
    assert key_no_host == _cache_service.generate_cache_key(payload, None)
    assert len(key_no_host) == 64 and all(c in "0123456789abcdef" for c in key_no_host)

    # Host-sensitivity: same payload, different/absent host → different keys.
    key_host = _cache_service.generate_cache_key(payload, target_host)
    key_other = _cache_service.generate_cache_key(payload, "api.other.com")
    assert key_host != key_no_host, "cache key did not vary by presence of host"
    assert key_host != key_other, "cache key did not vary by target_host"

    # Payload-sensitivity.
    assert _cache_service.generate_cache_key("other", target_host) != key_host


@pytest.mark.asyncio
async def test_cache_and_retrieve_auth_result(docker_setup, request):
    """A cached AuthResult round-trips through Redis, upstream-header fields too."""
    payload = f"test-payload-roundtrip-{uuid.uuid4()}"
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

    auth_result = AuthResult(
        api_key="sk-test-api-key-roundtrip",
        principal_info=principal_info,
        output_header="x-goog-api-key",
        output_prefix="",
    )
    assert await _cache_service.cache_auth_result(payload, TARGET_HOST, auth_result)

    cached = await _cache_service.get_cached_auth_result(payload, TARGET_HOST)

    assert cached is not None, "Failed to retrieve cached auth result"
    assert cached.api_key == auth_result.api_key
    assert cached.output_header == "x-goog-api-key"
    assert cached.output_prefix == ""
    assert cached.principal_info.account_id == principal_info.account_id
    assert cached.principal_info.principal == principal_info.principal
    assert await _cache_service.get_cached_auth_result(payload, "api.other.com") is None


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

    cached = await _cache_service.get_cached_auth_result(payload, TARGET_HOST)

    assert cached is not None, "Failed to retrieve cached auth result"
    assert cached.api_key == api_key
    assert cached.principal_info.account_id == principal_info.account_id
