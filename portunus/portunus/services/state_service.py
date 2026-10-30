"""
Redis state management service module.

This module contains the StateService class, which is responsible for
managing Redis connections and providing access to Redis clients.
"""

import asyncio
import contextlib
import hashlib
import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any, Optional

import aiobotocore.session
import redis.asyncio as aioredis
from aiobotocore.config import AioConfig
from redis.exceptions import ConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

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
    """Async CM yielding a pooled AWS client.

    Unlike ``aiobotocore``'s ``create_client`` CM, ``__aexit__`` does NOT close
    the client — it stays in :class:`StateService`'s credential-keyed pool,
    closed on LRU eviction (after a grace period) and on
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
    """Duck-typed ``aiobotocore.Session`` subset backed by the client pool.

    Drop-in for per-request ``async with session.create_client(...)`` sites
    (STS in ``AuthService.get_aws_identity``, Secrets Manager in
    ``SecretsService.fetch_secret``). A plain session rebuilds an aiohttp pool
    + TLS context (~200ms cold) on every call; this reuses one client per
    (service, credential set), like the Kinesis singleton.
    """

    def __init__(self, state_service: "StateService") -> None:
        self._state_service = state_service

    @property
    def base_session(self) -> aiobotocore.session.AioSession:
        """The full session behind the pool.

        For callers needing more than ``create_client(credentials,
        endpoint_url)`` — e.g. federation minting, whose per-mint credentials
        would never hit the pool anyway.
        """
        return self._state_service.boto_session

    def create_client(self, service_name: str, **kwargs: Any) -> _PooledClientContext:
        """Return a non-closing async CM around a pooled client."""
        return _PooledClientContext(self._state_service, service_name, kwargs)


def _build_redis_pool() -> aioredis.BlockingConnectionPool:
    """Build the shared Redis pool from config.

    ``BlockingConnectionPool`` rather than the default pool: at the cap the
    default raises ``ConnectionError("Too many connections")`` immediately,
    which the auth path treats as a Redis failure and falls through to STS +
    Secrets Manager — a burst turns into a stampede. Blocking for up to
    ``pool_timeout_seconds`` queues the burst on the pool instead, and a
    request whose wait expires is rejected by :meth:`StateService.execute_redis`
    rather than falling through.
    """
    redis_config = config.redis
    connection_kwargs: dict[str, Any] = {
        "host": redis_config.host,
        "port": redis_config.port,
        "password": redis_config.password or None,
        "decode_responses": True,
        "socket_timeout": 5.0,
        "socket_connect_timeout": 2.0,
        "retry_on_timeout": True,
        "health_check_interval": redis_config.health_check_interval_seconds,
    }
    if redis_config.use_tls:
        connection_kwargs["connection_class"] = aioredis.SSLConnection
        connection_kwargs["ssl_cert_reqs"] = "required"
    return aioredis.BlockingConnectionPool(
        max_connections=redis_config.max_connections,
        # Typed int in redis-py, but it only feeds asyncio.timeout.
        timeout=redis_config.pool_timeout_seconds,  # type: ignore[arg-type]
        **connection_kwargs,
    )


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
        # Kinesis client is a singleton per process: opened once via an
        # AsyncExitStack (avoiding the ~200ms per-entry aiohttp+TLS setup)
        # and closed in ``close()``.
        self._aws_stack: Optional[contextlib.AsyncExitStack] = None
        self._kinesis_client: Optional[Any] = None
        self._aws_client_lock = asyncio.Lock()
        # Credential-keyed AWS client pool (STS / Secrets Manager): built with
        # the *caller's* temporary creds, so pooled per (service, credential
        # set) with a bounded LRU. Values are ``(ctx, client)``; ``ctx`` must
        # be exited to close the client.
        self._cred_client_pool: "OrderedDict[str, tuple[Any, Any]]" = OrderedDict()
        # Grace-period close tasks for evicted clients, kept so ``close()``
        # finishes them deterministically.
        self._retiring_clients: dict[asyncio.Task[None], "_ClientRetirement"] = {}

    # Bounded LRU (each entry is an aiohttp pool + TLS context); beyond this
    # the least-recently-used client is retired. 64 is generous per sidecar.
    _CRED_CLIENT_POOL_MAX = 64
    # Grace before closing an evicted client so an in-flight call can finish;
    # well above the 4s auth deadline on STS/Secrets calls.
    _CRED_CLIENT_EVICT_GRACE_S = 30.0

    def pooled_boto_session(self) -> PooledBotoSession:
        """Return a session-like adapter that reuses pooled AWS clients."""
        return PooledBotoSession(self)

    @staticmethod
    def _cred_pool_key(service_name: str, parts: tuple[Optional[str], ...]) -> str:
        """Digest a (service, credentials, endpoint) tuple into a pool key.

        Components are length-prefixed so differing tuples can't collide, and
        raw secret key material isn't retained as a dict key.
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

        Lock-free: all callers share the single grpc.aio loop and no ``await``
        separates lookup from return on the hit path. On a same-key race the
        loser closes its own unshared client and returns the winner's.
        """
        key = self._cred_pool_key(
            service_name,
            (aws_access_key_id, aws_secret_access_key, aws_session_token, endpoint_url),
        )
        entry = self._cred_client_pool.get(key)
        if entry is not None:
            self._cred_client_pool.move_to_end(key)
            return entry[1]

        # type-ignore: types-aiobotocore keys create_client overloads on
        # literal service names; service_name here is dynamic.
        ctx = self.boto_session.create_client(  # type: ignore[call-overload]
            service_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            endpoint_url=endpoint_url,
        )
        client = await ctx.__aenter__()

        raced = self._cred_client_pool.get(key)
        if raced is not None:
            # Raced: another coroutine created it while we awaited; close ours
            # (unshared) and use theirs.
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
        - Connection limits based on configuration; at the limit a command
          waits for a free connection instead of failing

        Returns:
            Optional[aioredis.Redis]: Redis client if connection successful, None
                                      otherwise

        """
        if self.redis_client is None:
            try:
                # Log Redis connection parameters before connecting
                logger.info(
                    "Connecting to Redis at %s:%d (password_set=%s)",
                    config.redis.host,
                    config.redis.port,
                    bool(config.redis.password),
                )

                # Create Redis client with built-in connection pooling
                self.redis_client = aioredis.Redis.from_pool(_build_redis_pool())

                # Verify authentication with a simple command
                ping_result = await self.redis_client.ping()
                logger.info(
                    f"Successfully connected to Redis at "
                    f"{config.redis.host}:{config.redis.port}, "
                    f"ping result: {ping_result}"
                )
            except (RedisTimeoutError, TimeoutError):
                raise
            except Exception as e:
                logger.exception(f"Redis connection failure traceback: {e}")
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
                logger.error(f"Error closing Redis client: {e}")
            finally:
                self.redis_client = None

    async def execute_redis[T](
        self, operation: Callable[[aioredis.Redis], Awaitable[T]]
    ) -> Optional[T]:
        """Run a Redis operation on the shared client.

        Returns ``None`` when no client is available. The blocking pool queues
        the command for up to ``REDIS_POOL_TIMEOUT_SECONDS``; if that wait
        expires, redis-py raises ``ConnectionError("No connection available.")``
        chained from the wait's ``TimeoutError``. That one case is re-raised as
        a ``TimeoutError`` so the auth path rejects the request instead of
        treating it as a cache miss — a saturated pool must not fall through to
        STS and Secrets Manager. Every other ``ConnectionError`` (refused,
        reset, failover) propagates unchanged and callers treat it as a miss.

        Raises:
            TimeoutError: If the wait for a pooled connection expires.
        """
        client = await self.get_redis_client()
        if not client:
            logger.warning("Redis client unavailable for cache operation")
            return None

        try:
            return await operation(client)
        except ConnectionError as e:
            if isinstance(e.__cause__, TimeoutError):
                logger.warning(
                    "Timed out after %.1fs waiting for a pooled Redis connection",
                    config.redis.pool_timeout_seconds,
                )
                raise TimeoutError(
                    "Timed out waiting for a pooled Redis connection"
                ) from e
            raise

    async def _ensure_aws_stack(self) -> contextlib.AsyncExitStack:
        """Lazily open the shared exit stack used by the AWS client singletons."""
        if self._aws_stack is None:
            async with self._aws_client_lock:
                if self._aws_stack is None:
                    self._aws_stack = contextlib.AsyncExitStack()
                    await self._aws_stack.__aenter__()
        return self._aws_stack

    async def get_kinesis_client(self):
        """
        Get the shared Kinesis Data Streams client, creating it on first use.

        One client is kept for the lifetime of the process: constructing an
        aiobotocore client builds a fresh SSL context and parses the CA bundle
        (~30-40 ms of CPU), so never create one per call.

        Tight timeouts and a single SDK retry: a hung or throttled PutRecords
        call holds the publish worker, and while it waits the bounded queue
        fills and sheds audit. botocore's defaults (60 s read, legacy retries)
        turned one stalled call into a minute of dropped records.

        Returns:
            A Kinesis Data Streams client instance
        """
        if self._kinesis_client is None:
            stack = await self._ensure_aws_stack()
            async with self._aws_client_lock:
                if self._kinesis_client is None:
                    self._kinesis_client = await stack.enter_async_context(
                        self.boto_session.create_client(
                            "kinesis",
                            config=AioConfig(
                                user_agent="portunus-audit",
                                connect_timeout=2,
                                read_timeout=5,
                                retries={"mode": "standard", "max_attempts": 2},
                            ),
                        )
                    )
        return self._kinesis_client

    async def close(self) -> None:
        """Tear down cached AWS clients. Called on graceful shutdown."""
        while self._cred_client_pool:
            _, (ctx, _) = self._cred_client_pool.popitem(last=False)
            with contextlib.suppress(Exception):
                await ctx.__aexit__(None, None, None)
        # Cut grace timers short and close their clients; the explicit
        # (idempotent) ``retirement.close()`` covers tasks cancelled before
        # they ran.
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
            self._kinesis_client = None
