"""Redis and pooled-AWS-client state management (the StateService class)."""

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
    (service, credential set), like the Firehose singleton.
    """

    def __init__(self, state_service: "StateService") -> None:
        self._state_service = state_service

    def create_client(self, service_name: str, **kwargs: Any) -> _PooledClientContext:
        """Return a non-closing async CM around a pooled client."""
        return _PooledClientContext(self._state_service, service_name, kwargs)


class StateService:
    """Manages Redis connections and pooled AWS clients.

    Attributes:
        redis_client: The Redis client instance.
    """

    def __init__(self) -> None:
        """Initialize the StateService."""
        self.redis_client: Optional[aioredis.Redis] = None
        self.boto_session = aiobotocore.session.get_session()
        # Firehose client is a singleton per process: opened once via an
        # AsyncExitStack (avoiding the ~200ms per-entry aiohttp+TLS setup)
        # and closed in ``close()``.
        self._aws_stack: Optional[contextlib.AsyncExitStack] = None
        self._firehose_client: Optional[Any] = None
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
        """Lazily initialize and return a shared async Redis client.

        Returns:
            The Redis client, or None if the connection failed.

        Raises:
            RedisError: If Redis configuration is invalid.
        """
        if self.redis_client is None:
            try:
                # Password length is a side channel — log a bool, not the value.
                logger.info(
                    "Connecting to Redis at %s:%d (password_set=%s)",
                    config.redis.host,
                    config.redis.port,
                    bool(config.redis.password),
                )

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

                ping_result = await self.redis_client.ping()
                logger.info(
                    f"Successfully connected to Redis at "
                    f"{config.redis.host}:{config.redis.port}, "
                    f"ping result: {ping_result}"
                )
            except Exception as e:
                # No traceback — aioredis TLS/auth exceptions can include
                # sensitive bytes.
                logger.error("Redis connection failure: %s", type(e).__name__)
                self.redis_client = None
                return None
        return self.redis_client

    async def close_redis_client(self) -> None:
        """Close the Redis client connection pool (call on shutdown)."""
        if self.redis_client is not None:
            try:
                await self.redis_client.aclose()
                logger.info("Redis client connection pool closed")
            except Exception as e:
                logger.error("Error closing Redis client: %s", type(e).__name__)
            finally:
                self.redis_client = None

    async def acquire_redis_connection(self, max_retries=8):
        """Acquire a Redis connection with exponential-backoff retry.

        Provides backpressure by making callers wait when Redis is overloaded.
        (Caveat: the ping() here also adds load.)

        Args:
            max_retries: Maximum retry attempts (default: 8).

        Returns:
            Redis client if successful, None otherwise.
        """
        client = await self.get_redis_client()
        if not client:
            return None

        retry_count = 0
        while retry_count <= max_retries:
            try:
                await client.ping()
                return client
            except (MaxConnectionsError, ConnectionError) as e:
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
        """Check if Redis is available."""
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
            self._firehose_client = None
