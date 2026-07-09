"""Tests for the Redis API authentication response caching functionality."""

import os
import sys
import uuid

import pytest
import redis.asyncio as aioredis
from conftest import dump_container_logs

# Add portunus to Python path before importing portunus.*
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus"))

from portunus.models import AuthResult, PrincipalInfo, SigningKey  # noqa: E402
from portunus.services.cache_service import CacheService  # noqa: E402
from portunus.services.state_service import StateService  # noqa: E402

# Global test instances to reuse across tests
_test_redis_client = None
_state_service = StateService()
_cache_service = CacheService(_state_service)


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
    """Cache-key contract (host+payload hashed independently, host normalised).

    Asserts the properties that matter for correctness/security rather than
    re-deriving the internal hash: determinism, host- and payload-sensitivity
    (so a bearer authorised for provider A can't re-use a cached api_key on
    provider B), and host normalisation (equivalent hosts share one entry).
    The exact construction is unit-tested in portunus/tests/test_cache_key.py.
    """
    payload = "test-payload"
    target_host = "api.example.com"

    # Deterministic + Redis-safe (64-char sha256 hex).
    key_no_host = _cache_service.generate_cache_key(payload)
    assert key_no_host == _cache_service.generate_cache_key(payload)
    assert len(key_no_host) == 64 and all(c in "0123456789abcdef" for c in key_no_host)

    # Host-sensitivity: same payload, different/absent host → different keys.
    key_host = _cache_service.generate_cache_key(payload, target_host)
    key_other = _cache_service.generate_cache_key(payload, "api.other.com")
    assert key_host != key_no_host, "cache key did not vary by presence of host"
    assert key_host != key_other, "cache key did not vary by target_host"

    # Payload-sensitivity.
    assert _cache_service.generate_cache_key("other", target_host) != key_host

    # Host normalisation: case + default :443 are equivalent (share one entry).
    assert (
        _cache_service.generate_cache_key(payload, "API.Example.com:443") == key_host
    ), "host normalisation (case/default-port) not applied to the cache key"


@pytest.mark.asyncio
async def test_cache_and_retrieve_with_none_signing_key(docker_setup, request):
    """Regression test for None signing_key cache retrieval.

    Tests bug where retrieving cached auth with None signing_key would fail
    with 'NoneType' object is not subscriptable. This is the common case
    where API keys don't require request signing.
    """
    # Create test data with None signing_key (the common case)
    payload = f"test-payload-none-signing-{uuid.uuid4()}"
    api_key = "sk-test-api-key-no-signing"
    signing_key = None  # Most API keys don't require signing
    principal_info = PrincipalInfo(
        account_id="123456789012",
        principal="test-principal-no-signing",
        session_name="test-session",
    )

    # Set up Redis connection
    test_client = await get_test_redis_client()
    original_state_redis_client = _state_service.redis_client
    _state_service.redis_client = test_client

    def cleanup():
        _state_service.redis_client = original_state_redis_client

    request.addfinalizer(cleanup)

    # Cache the auth result with None signing_key
    auth_result = AuthResult(
        api_key=api_key, signing_key=signing_key, principal_info=principal_info
    )
    result = await _cache_service.cache_auth_result(payload, auth_result)
    assert result is True, "Failed to cache auth result"

    # Now retrieve it - this is where the bug was occurring
    cached = await _cache_service.get_cached_auth_result(payload)

    # Verify we got the data back without error
    assert cached is not None, "Failed to retrieve cached auth result"
    assert cached.api_key == api_key, "Retrieved API key doesn't match"
    assert cached.signing_key is None, "signing_key should be None"
    assert cached.principal_info.account_id == principal_info.account_id
    assert cached.principal_info.principal == principal_info.principal


@pytest.mark.asyncio
async def test_cache_and_retrieve_with_signing_key(docker_setup, request):
    """Test caching and retrieving auth with signing_key present.

    Tests the less common case where API keys require request signing
    (e.g., certain labs + models).
    """
    # Create test data with a signing_key
    payload = f"test-payload-with-signing-{uuid.uuid4()}"
    api_key = "sk-test-api-key-with-signing"
    signing_key = SigningKey(
        provider_id="signingkey_test123",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test-key-id",
    )
    principal_info = PrincipalInfo(
        account_id="123456789012",
        principal="test-principal-with-signing",
        session_name="test-session",
    )

    # Set up Redis connection
    test_client = await get_test_redis_client()
    original_state_redis_client = _state_service.redis_client
    _state_service.redis_client = test_client

    def cleanup():
        _state_service.redis_client = original_state_redis_client

    request.addfinalizer(cleanup)

    # Cache the auth result with signing_key
    auth_result = AuthResult(
        api_key=api_key, signing_key=signing_key, principal_info=principal_info
    )
    result = await _cache_service.cache_auth_result(payload, auth_result)
    assert result is True, "Failed to cache auth result"

    # Retrieve it
    cached = await _cache_service.get_cached_auth_result(payload)

    # Verify we got the data back
    assert cached is not None, "Failed to retrieve cached auth result"
    assert cached.api_key == api_key, "Retrieved API key doesn't match"
    assert cached.signing_key is not None, "signing_key should not be None"
    assert cached.signing_key.provider_id == signing_key.provider_id
    assert cached.signing_key.kms_key_arn == signing_key.kms_key_arn
    assert cached.principal_info.account_id == principal_info.account_id
    assert cached.principal_info.principal == principal_info.principal


@pytest.mark.asyncio
async def test_cache_api_key_redis_error():
    """Cache-key generation is deterministic without a live Redis.

    NOTE: despite the name this exercises no Redis error path — it is
    effectively redundant with ``test_generate_cache_key``. Flagged for the
    cleanup pass as a deletion/rename candidate; kept green in the meantime
    with a self-consistency check that isn't coupled to the hash construction.
    """
    payload = "test-payload"
    assert _cache_service.generate_cache_key(
        payload
    ) == _cache_service.generate_cache_key(payload)
