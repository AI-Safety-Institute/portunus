"""
Redis state management service module.

This module contains the StateService class, which is responsible for
managing Redis connections and providing access to Redis clients.
"""

import asyncio
import contextlib
import hashlib
import logging
import random
from collections import OrderedDict
from typing import Any, Optional

import aiobotocore.session
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError, MaxConnectionsError

from portunus.config import config

logger = logging.getLogger("api.access")


class _ClientRetirement:
    """Idempotent closer for an LRU-evicted pooled client's context."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._closed = False

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            await self._ctx.__aexit__(None, None, None)


class _PooledClientContext:
    """Async context manager yielding a pooled AWS client.

    Unlike the context manager returned by
    ``aiobotocore.session.Session.create_client`` this does NOT close the
    client on ``__aexit__`` — the client stays alive in the
    :class:`StateService` credential-keyed pool for reuse. The pool closes
    clients on LRU eviction (after a grace period) and on
    :meth:`StateService.close`.
    """

    def __init__(
        self, state_service: "StateService", service_name: str, kwargs: dict[str, Any]
    ) -> None:
        self._state_service = state_service
        self._service_name = service_name
        self._kwargs = kwargs

    async def __aenter__(self) -> Any:
        return await self._state_service.get_pooled_aws_client(
            self._service_name, **self._kwargs
        )

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        # Deliberate no-op: the pooled client is shared and long-lived.
        return None


class PooledBotoSession:
    """Duck-typed subset of an aiobotocore ``Session`` backed by the pool.

    Drop-in for call sites that do
    ``async with session.create_client(...) as client:`` per request (STS in
    ``AuthService.get_aws_identity``, Secrets Manager in
    ``SecretsService.fetch_secret``). A plain session's ``create_client``
    builds a fresh aiohttp connection pool + TLS context (~200ms cold) on
    every call, paid twice per auth cache-miss — a latency spike on
    cache-miss storms (deploy / TTL-expiry waves). With this adapter the
    underlying client is created once per (service, credential set) and
    reused, mirroring the Firehose singleton in :class:`StateService`.
    """

    def __init__(self, state_service: "StateService") -> None:
        self._state_service = state_service

    def create_client(self, service_name: str, **kwargs: Any) -> _PooledClientContext:
        """Return a non-closing async CM around a pooled client."""
        return _PooledClientContext(self._state_service, service_name, kwargs)


class StateService:
    """
    Service for managing Redis connections and state.

    This service is responsible for creating and managing Redis clients,
    handling connection pooling, and providing access to Redis for other
    services.

    Attributes:
        redis_client: The Redis client instance
    """

    def __init__(self) -> None:
        """Initialize the StateService."""
        self.redis_client: Optional[aioredis.Redis] = None
        self.boto_session = aiobotocore.session.get_session()
        # aiobotocore clients are async context managers; entering them
        # creates a fresh aiohttp connection pool + TLS context (~200ms
        # cold start). Re-entering on every publish flattens throughput
        # — instead we keep a singleton client per service, opened once
        # via an AsyncExitStack and closed in ``close()`` on shutdown.
        self._aws_stack: Optional[contextlib.AsyncExitStack] = None
        self._firehose_client: Optional[Any] = None
        self._aws_client_lock = asyncio.Lock()
        # Credential-keyed AWS client pool (STS / Secrets Manager). Unlike
        # Firehose (task-role creds, one client per process), these clients
        # are built with the *caller's* temporary credentials, so we pool
        # per (service, credential set) with a bounded LRU. Values are
        # ``(ctx, client)`` where ``ctx`` is the aiobotocore context
        # manager that must be exited to close the client.
        self._cred_client_pool: "OrderedDict[str, tuple[Any, Any]]" = OrderedDict()
        # Grace-period close tasks for LRU-evicted clients: task -> ctx
        # closer. Kept so ``close()`` can finish them deterministically
        # (a cancelled task that never started skips its own cleanup).
        self._retiring_clients: dict[asyncio.Task[None], "_ClientRetirement"] = {}

    # Bounded LRU: each entry is an aiohttp pool + TLS context. 64 distinct
    # live credential sets per service is generous for a single sidecar;
    # beyond that the least-recently-used client is retired.
    _CRED_CLIENT_POOL_MAX = 64
    # Grace before closing an LRU-evicted client, so an in-flight call on it
    # can finish. Well above the 4s auth deadline bounding STS/Secrets calls.
    _CRED_CLIENT_EVICT_GRACE_S = 30.0

    def pooled_boto_session(self) -> PooledBotoSession:
        """Return a session-like adapter that reuses pooled AWS clients."""
        return PooledBotoSession(self)

    @staticmethod
    def _cred_pool_key(service_name: str, parts: tuple[Optional[str], ...]) -> str:
        """Digest a (service, credentials, endpoint) tuple into a pool key.

        Components are length-prefixed before hashing so no concatenation of
        differing components can collide, and the raw secret key material is
        not retained as a dict key.
        """
        digest = hashlib.sha256()
        for part in (service_name, *parts):
            raw = (part or "").encode("utf-8")
            digest.update(len(raw).to_bytes(4, "big"))
            digest.update(raw)
        return digest.hexdigest()

    async def get_pooled_aws_client(
        self,
        service_name: str,
        *,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> Any:
        """Get (or create) a pooled AWS client for a credential set.

        Safe without a lock: all callers run on the single grpc.aio event
        loop and there is no ``await`` between the pool lookup and return on
        the hit path. On a same-key creation race the loser closes its own
        client (which no caller has seen) and returns the winner's.
        """
        key = self._cred_pool_key(
            service_name,
            (aws_access_key_id, aws_secret_access_key, aws_session_token, endpoint_url),
        )
        entry = self._cred_client_pool.get(key)
        if entry is not None:
            self._cred_client_pool.move_to_end(key)
            return entry[1]

        ctx = self.boto_session.create_client(
            service_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            endpoint_url=endpoint_url,
        )
        client = await ctx.__aenter__()

        raced = self._cred_client_pool.get(key)
        if raced is not None:
            # Another coroutine created this client while we awaited; ours
            # has no users yet, so close it immediately and share theirs.
            with contextlib.suppress(Exception):
                await ctx.__aexit__(None, None, None)
            return raced[1]

        self._cred_client_pool[key] = (ctx, client)
        while len(self._cred_client_pool) > self._CRED_CLIENT_POOL_MAX:
            _, (old_ctx, _) = self._cred_client_pool.popitem(last=False)
            self._retire_client(old_ctx)
        return client

    def _retire_client(self, ctx: Any) -> None:
        """Close an evicted client after a grace period (in the background)."""
        retirement = _ClientRetirement(ctx)

        async def _close_after_grace() -> None:
            try:
                await asyncio.sleep(self._CRED_CLIENT_EVICT_GRACE_S)
            except asyncio.CancelledError:
                # Shutdown: skip the remaining grace and close now.
                pass
            await retirement.close()

        task = asyncio.get_running_loop().create_task(_close_after_grace())
        self._retiring_clients[task] = retirement
        task.add_done_callback(lambda t: self._retiring_clients.pop(t, None))

    async def get_redis_client(self) -> Optional[aioredis.Redis]:
        """
        Get async Redis client for non-blocking operations.

        This method lazily initializes a Redis client the first time it's called,
        and returns the same client on subsequent calls. It handles connection
        errors gracefully and logs connection status.

        The client uses a connection pool with the following features:
        - Connection retry with exponential backoff
        - Pool health checks to remove dead connections
        - Connection limits based on configuration

        Returns:
            Optional[aioredis.Redis]: Redis client if connection successful, None
                                      otherwise

        Raises:
            RedisError: If Redis configuration is invalid
        """
        if self.redis_client is None:
            try:
                # Log Redis connection target. Password length is a side
                # channel — emit a bool instead.
                logger.info(
                    "Connecting to Redis at %s:%d (password_set=%s)",
                    config.redis.host,
                    config.redis.port,
                    bool(config.redis.password),
                )

                # Create Redis client with built-in connection pooling
                self.redis_client = aioredis.Redis(
                    host=config.redis.host,
                    port=config.redis.port,
                    password=config.redis.password if config.redis.password else None,
                    decode_responses=True,
                    max_connections=config.redis.max_connections,
                    ssl=config.redis.use_tls,
                    ssl_cert_reqs="required" if config.redis.use_tls else "none",
                    socket_timeout=5.0,
                    socket_connect_timeout=2.0,
                    retry_on_timeout=True,
                    health_check_interval=5,
                )

                # Verify authentication with a simple command
                ping_result = await self.redis_client.ping()
                logger.info(
                    f"Successfully connected to Redis at "
                    f"{config.redis.host}:{config.redis.port}, "
                    f"ping result: {ping_result}"
                )
            except Exception as e:
                # Don't log full traceback — TLS / auth exceptions from
                # aioredis can include sensitive bytes (rarely, but worth
                # bounding).
                logger.error("Redis connection failure: %s", type(e).__name__)
                self.redis_client = None  # Reset to None in case of error
                return None
        return self.redis_client

    async def close_redis_client(self) -> None:
        """
        Close the Redis client connection pool.

        This method should be called during application shutdown to properly
        close all Redis connections in the pool.
        """
        if self.redis_client is not None:
            try:
                await self.redis_client.aclose()
                logger.info("Redis client connection pool closed")
            except Exception as e:
                logger.error("Error closing Redis client: %s", type(e).__name__)
            finally:
                self.redis_client = None

    async def acquire_redis_connection(self, max_retries=8):
        """
        Acquire a Redis connection with exponential backoff retry.

        This provides backpressure by making callers wait for a client
        if the redis server is overloaded. Note that the ping() here
        ALSO creates load, so we might want to rethink this.

        Args:
            max_retries: Maximum number of retry attempts (default: 8)

        Returns:
            Redis client if successful, None otherwise
        Note:
            This method is intended for high-load scenarios where connections
            may be temporarily exhausted.
        """
        client = await self.get_redis_client()
        if not client:
            return None

        retry_count = 0
        while retry_count <= max_retries:
            try:
                # Attempt a simple ping to test connection acquisition
                await client.ping()
                return client
            except (MaxConnectionsError, ConnectionError) as e:
                # Check for "Too many connections" in the error message
                if "Too many connections" in str(e) and retry_count < max_retries:
                    retry_count += 1
                    backoff = min(0.1 * (1.5**retry_count), 1.0) * (
                        0.8 + 0.4 * random.random()
                    )
                    logger.warning(
                        f"Redis connection limit reached, retrying in {backoff:.2f}s "
                        f"(attempt {retry_count}/{max_retries})"
                    )
                    await asyncio.sleep(backoff)
                else:
                    raise e
        return None

    async def health_check(self) -> bool:
        """
        Check if Redis is available.

        Returns:
            bool: True if Redis is available, False otherwise
        """
        client = await self.get_redis_client()
        if client is None:
            return False

        try:
            await client.ping()
            return True
        except Exception as e:
            logger.error("Redis health check failed: %s", type(e).__name__)
            return False

    async def _ensure_aws_stack(self) -> contextlib.AsyncExitStack:
        """Lazily open the shared exit stack used by the AWS client singletons."""
        if self._aws_stack is None:
            async with self._aws_client_lock:
                if self._aws_stack is None:
                    self._aws_stack = contextlib.AsyncExitStack()
                    await self._aws_stack.__aenter__()
        return self._aws_stack

    async def get_firehose_client(self):
        """Return a shared Firehose direct-PUT client (created once per process)."""
        if self._firehose_client is None:
            stack = await self._ensure_aws_stack()
            async with self._aws_client_lock:
                if self._firehose_client is None:
                    self._firehose_client = await stack.enter_async_context(
                        self.boto_session.create_client("firehose")
                    )
        return self._firehose_client

    async def close(self) -> None:
        """Tear down cached AWS clients. Called on graceful shutdown."""
        # Close every pooled credential-keyed client.
        while self._cred_client_pool:
            _, (ctx, _) = self._cred_client_pool.popitem(last=False)
            with contextlib.suppress(Exception):
                await ctx.__aexit__(None, None, None)
        # Cut grace-period timers short and close their clients. The
        # explicit ``retirement.close()`` (idempotent) covers tasks that
        # were cancelled before they ever ran.
        retiring = list(self._retiring_clients.items())
        for task, _ in retiring:
            task.cancel()
        if retiring:
            await asyncio.gather(
                *(task for task, _ in retiring), return_exceptions=True
            )
            for _, retirement in retiring:
                await retirement.close()

        if self._aws_stack is not None:
            await self._aws_stack.__aexit__(None, None, None)
            self._aws_stack = None
            self._firehose_client = None
