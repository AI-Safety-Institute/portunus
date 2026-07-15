# Runbook: Flush the Portunus auth cache

## What this does

Portunus caches successful authorisation results (the resolved upstream API key
plus principal/signing metadata) in two layers: a **single shared ElastiCache
(Redis)**, keyed by `sha256(target_host:payload)` with a per-entry TTL, and a
short-lived **in-process copy inside each task**. This runbook flushes both,
fleet-wide, by calling the application's own `CacheService.flush_all()`, which
issues a Redis `FLUSHDB` and then rewrites a flush token in Redis.

**One flush is fleet-wide** — you do not need to repeat it per task. The task
you run it on converges instantly; every other task re-checks the flush token
at most `CACHE_FLUSH_POLL_SECONDS` (default 5s) apart and drops its in-process
copy on change, so the whole fleet stops serving flushed entries within a few
seconds.

## When to use it

Reach for this only when you need cached auth state gone *now*:

- **Suspected key compromise** — an upstream API key in a cached entry may have
  leaked and you want every subsequent request to re-authenticate against AWS
  (Secrets Manager) immediately rather than serving a stale cached key.
- **Secret rotation you don't want to wait out** — you rotated a secret in
  Secrets Manager and need Portunus to pick up the new value before the cached
  entry's TTL expires.

Otherwise, **do nothing**: the cache's `volatile-ttl` eviction policy plus the
per-entry TTL (`CACHE_DURATION`) self-heal. Routine rotations converge without a
flush once the TTL lapses.

> A flush is not free: every cached principal must re-authenticate against STS +
> Secrets Manager on its next request, briefly raising latency and AWS API load
> on the hot path. Use it deliberately, not as routine hygiene.

If a scoped (per-provider or per-tenant) flush becomes a recurring need, the
right fix is cache namespacing (a key prefix + `SCAN`-based deletion) — do not
improvise a `KEYS`-pattern delete against the production cache on the hot path.

## Prerequisites

- **ECS Exec enabled** on the Portunus service (`enableExecuteCommand: true`).
  This is configured in the api-key-proxy infrastructure.
- The **Session Manager plugin** installed locally (`session-manager-plugin`);
  the AWS CLI uses it to open the exec channel.
- IAM permission to run `ecs:ExecuteCommand` against the cluster/task (and the
  task role must carry the `ssmmessages:*` channel actions).
- AWS credentials for the correct account/region (the Portunus fleet's).

## Procedure

```bash
# Identify the cluster and service (fill these in for the target environment).
CLUSTER=<portunus-cluster>; SVC=<portunus-service>

# Pick any running task — the cache is shared, so one task is enough.
TASK=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$SVC" \
  --query 'taskArns[0]' --output text)

# Exec into the Portunus container and flush via the app's own Redis config.
aws ecs execute-command --cluster "$CLUSTER" --task "$TASK" --container portunus --interactive \
  --command "portunus flush-cache"
```

A successful run prints:

```
flushed: True
```

`flushed: False` means Redis was unreachable from the task (nothing was flushed —
see the fallback below). A non-zero exit / `CacheError` traceback means the
`FLUSHDB` or the flush-token write failed; **re-run** (the command is idempotent
— without a fresh token the other tasks converge only by their in-process TTL),
and if it persists use the fallback.

> The `--container` name must match the container in the task definition. It is
> `portunus` in the api-key-proxy CDK; adjust if your task definition names it
> differently.

## Why this form

- **`portunus flush-cache` reuses the app's own Redis configuration.** It
  drives `CacheService.flush_all()` with a default `StateService` that reads
  the same `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` (TLS + AUTH) from the
  task environment that the live servicers use — so you connect exactly as
  Portunus does, with no separate credentials to manage.
- **The container has the `portunus` CLI and `redis` Python library but not
  `redis-cli` or `grpcurl`.** Driving the flush through the app code is the
  only in-image path; there is no network-reachable admin endpoint.
- **One exec suffices**: Redis is shared, and the rewritten flush token is the
  broadcast that makes every other task drop its in-process copy.
- **It is auditable and IAM-gated.** `ecs:ExecuteCommand` is gated by IAM, and the
  session is logged via CloudTrail (the `ExecuteCommand` API call) and SSM session
  history.

## Fallback (Portunus tasks unhealthy / exec unavailable)

If no Portunus task is healthy enough to exec into, flush Redis directly from any
foothold inside the VPC whose security group is allowed to reach the cache on
`6379`:

```bash
# <primary-endpoint>: ElastiCache primary endpoint
# <auth-token>: the Redis AUTH token from Secrets Manager (do NOT echo it)
redis-cli -h <primary-endpoint> --tls -a <auth-token> FLUSHDB
redis-cli -h <primary-endpoint> --tls -a <auth-token> SET cache:flush-token "$(uuidgen)"
```

Pull the AUTH token from Secrets Manager rather than pasting a literal (avoid
leaving the token in shell history). This bypasses the application entirely and
talks to the same shared cache, so it is likewise fleet-wide.

The `SET cache:flush-token` **is not optional**: it is the signal the tasks
poll to drop their in-process copies. `FLUSHDB` alone deletes the token key,
which only signals tasks that have seen a previous flush — on a fleet that has
never flushed, tasks would keep serving in-process entries until their local
TTL lapses. Always set a fresh token after a manual `FLUSHDB`, in that order
(token first would let a task re-fill from not-yet-flushed Redis).
