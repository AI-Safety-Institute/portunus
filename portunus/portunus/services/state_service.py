"""
Redis state management service module.

This module contains the StateService class, which is responsible for
managing Redis connections and providing access to Redis clients.
"""

import asyncio
import contextlib
import logging
import random
from typing import Any, Optional

import aiobotocore.session
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError, MaxConnectionsError

from portunus.config import config

logger = logging.getLogger("api.access")


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
        if self._aws_stack is not None:
            await self._aws_stack.__aexit__(None, None, None)
            self._aws_stack = None
            self._firehose_client = None
