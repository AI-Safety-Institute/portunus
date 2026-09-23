# Flush the Portunus auth cache

Portunus caches successful authorisation results in Redis. After rotating or
revoking credentials, use this procedure when waiting for cached credentials
to expire is insufficient.

`CacheService.flush_all()` issues Redis `FLUSHDB`: it deletes every key in
the configured Redis database, including keys belonging to other applications
if they share that database. One invocation affects every Portunus instance
using that database. Deployments with separate Redis databases require a
separate flush for each affected database.

A flush removes stored entries; it does not revoke upstream credentials,
terminate existing requests or WebSocket sessions, or cancel authentication
already in progress. Update the underlying credentials first. If immediate
revocation is required, also account for active requests and cache writes
already in flight.

## Run the flush

Use an authorised administrative shell in the intended Portunus container,
or an environment with the same installed package and Redis configuration.
Confirm the target environment and database before running the command.
The environment must provide the same `REDIS_HOST`, `REDIS_PORT`,
`REDIS_PASSWORD`, and `REDIS_USE_TLS` values as the running service.

```bash
python - <<'PY'
import asyncio

from portunus.services.cache_service import CacheService


async def main():
    cache = CacheService()
    try:
        if not await cache.flush_all():
            raise SystemExit("Cache flush failed: Redis unavailable")
        print("Auth cache flushed")
    finally:
        await cache.state_service.close_redis_client()


asyncio.run(main())
PY
```

Success prints `Auth cache flushed`. A nonzero exit means the operation was
not confirmed; inspect the error and Redis connectivity before retrying.

Subsequent cache misses re-authenticate through STS and Secrets Manager, so
expect a temporary increase in latency and AWS API traffic. Verify the next
request uses the intended credential state without printing the secret value.
Monitor authentication failures and Redis connectivity after the operation.

The gRPC backend has no HTTP cache-flush endpoint or `portunus flush-cache`
subcommand. Administrative shell access and its audit trail are configured by
the deployment platform.
