"""Redis state management service module.

Manages Redis connections for caching. AWS client management has been
moved to the backend implementations.
"""

import asyncio
import logging
import random
from typing import Optional

import redis.asyncio as aioredis
from aws_xray_sdk.core import xray_recorder
from redis.exceptions import ConnectionError, MaxConnectionsError

from portunus.config import config

logger = logging.getLogger("api.access")


class StateService:
    """Manages Redis connections and state.

    Handles connection pooling, health checks, and graceful shutdown
    for Redis.
    """

    def __init__(self) -> None:
        self.redis_client: Optional[aioredis.Redis] = None

    async def get_redis_client(self) -> Optional[aioredis.Redis]:
        """Get async Redis client, lazily initialised."""
        if self.redis_client is None:
            try:
                logger.info(
                    f"Connecting to Redis at"
                    f" {config.redis.host}:{config.redis.port}"
                    f" with password length:"
                    f" {len(config.redis.password or '')}"
                )

                self.redis_client = aioredis.Redis(
                    host=config.redis.host,
                    port=config.redis.port,
                    password=(config.redis.password if config.redis.password else None),
                    decode_responses=True,
                    max_connections=config.redis.max_connections,
                    ssl=config.redis.use_tls,
                    ssl_cert_reqs=("required" if config.redis.use_tls else "none"),
                    socket_timeout=5.0,
                    socket_connect_timeout=2.0,
                    retry_on_timeout=True,
                    health_check_interval=5,
                )

                ping_result = await self.redis_client.ping()
                logger.info(
                    f"Successfully connected to Redis at"
                    f" {config.redis.host}:{config.redis.port},"
                    f" ping result: {ping_result}"
                )
            except Exception as e:
                logger.exception(f"Redis connection failure traceback: {e}")
                self.redis_client = None
                return None
        return self.redis_client

    async def close_redis_client(self) -> None:
        """Close the Redis client connection pool."""
        if self.redis_client is not None:
            try:
                await self.redis_client.aclose()
                logger.info("Redis client connection pool closed")
            except Exception as e:
                logger.error(f"Error closing Redis client: {e}")
            finally:
                self.redis_client = None

    @xray_recorder.capture_async()  # type: ignore
    async def acquire_redis_connection(self, max_retries: int = 8):
        """Acquire a Redis connection with exponential backoff retry."""
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
                        f"Redis connection limit reached,"
                        f" retrying in {backoff:.2f}s"
                        f" (attempt"
                        f" {retry_count}/{max_retries})"
                    )
                    await asyncio.sleep(backoff)
                else:
                    raise
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
            logger.error(f"Redis health check failed: {e}")
            return False
