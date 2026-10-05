# Portunus (backend package)

The `portunus/` Python package is the gRPC servicer process that Envoy delegates auth and audit to. The root [README](../README.md) covers the overall system; this README is the dev-facing map of the package and how to run its unit tests.

For architecture and request flow (ext_authz `Check`, the auth cache tiers, ext_proc `Process`), see the [repo-root `CLAUDE.md`](../CLAUDE.md).

## Runtime

The container uses a glibc-based Python 3.12 image with native protobuf and
hiredis. The gRPC entrypoint uses uvloop on supported CPython platforms.

## Module map

```
portunus/
  cli.py            Console entry point (generates proxy auth payloads).
  config.py         Env-driven PortunusConfig (singleton at import time).
  exceptions.py     Service exception types (AuthenticationError, CredentialsError, ...).
  logging.py        StructuredLogFormatter: JSON log lines on stdout, enriched
                    with the request_id / trace_id contextvars from
                    request_context. Configured at import time.
  metrics.py        In-process metric aggregation (counters, delta sources,
                    gauges, bucketed distributions) flushed as CloudWatch
                    Embedded Metric Format JSON lines on a dedicated stdout
                    logger, bypassing the structured formatter.
  request_context.py  request_id / trace_id contextvars and the
                    x-amzn-trace-id Root= parser; no dependencies, so any
                    module can import it without side effects.
  models.py         Pydantic request models and dataclass audit record types
                    (MetadataRecord, RequestBodyRecord, ResponseBodyRecord,
                    WSSummaryRecord, JoinedLogRecord). Ships standalone into the
                    standalone analytics package, so all portunus.* imports here are lazy.
  util.py           Small helpers (timestamps, body chunking).

  grpc/
    server.py            Builds and starts the grpc.aio server; registers both
                         servicers, health, and reflection.
    auth_servicer.py     PortunusAuthServicer.Check — Envoy ext_authz, headers
                         only. Strips the prefix from the payload, calls
                         AuthService under a 9 s budget, writes the credential
                         header, and forwards upstream_auth_header / principal
                         metadata to ext_proc via dynamic_metadata.
    proc_servicer.py     PortunusProcessServicer.Process — Envoy ext_proc. Streams
                         request/response body chunks and post-101 WebSocket
                         frames into a bounded publish queue.
    frame_observer.py    wsproto-driven WebSocket frame parser (PerMessageDeflate
                         finalize()'d against the upstream's Sec-WebSocket-Extensions).
    proxy_auth.py        Helpers used by both servicers to validate the key in
                         the initial metadata and read the target host.

  services/
    auth_service.py            L1 cache -> Redis -> bounded full auth (STS
                               get-caller-identity + Secrets Manager fetch +
                               target-host validation) or a federation mint;
                               computes every cache tier's TTL.
    local_auth_cache.py        In-process LRU of auth results with a TTL and
                               single-flight loads.
    federation_service.py      Federation role assumption, STS web identity
                               token, one exchange adapter per *_wif type.
    secret_validation_service.py  parse_secret and target-host checks.
    secrets_service.py         aiobotocore Secrets Manager client; boto_session
                               is constructor-injectable for tests.
    cache_service.py           Redis-backed auth-response cache. The key is the
                               sha256 of the independently-hashed target_host
                               and payload digests.
    publish_service.py         Record builders, one per record type, plus Kinesis packing and `PutRecords`.
    publish_queue.py           Bounded async queue with headroom reserved for
                               metadata vs body submits.
    state_service.py           Redis client lifecycle and the per-credential
                               AWS client pool.
    payload_service.py         Base64 / JSON payload encode/decode.
    arn_service.py             Secret ARN parsing.
```

## gRPC-service environment variables

These gate the servicer process specifically; the root README documents the rest.

| Variable | Purpose |
|---|---|
| `GRPC_ENABLED` | Must be `true` (default `false`). The gRPC server is the process's only surface, so when it is unset/false `run()` logs "nothing to serve" and returns immediately instead of starting anything. Deployments must set it explicitly; `docker-compose.yaml` does so. |
| `GRPC_PORT` | gRPC listen port (default `9000`). |
| `GRPC_PROXY_API_KEY` | Key of at least 16 bytes matching proxy `PORTUNUS_API_KEY`, presented in `x-portunus-proxy-key` initial metadata; enforced by `grpc/proxy_auth.py`. |
| `GRPC_PROXY_API_KEY_OPTIONAL` | When `true`, an empty `GRPC_PROXY_API_KEY` is permitted (dev only). |

See `portunus/config.py` for the rest (Redis, auth caches, audit stream names, federation, header naming).

## CloudWatch EMF metrics

Portunus aggregates metrics in-process and flushes the interval as one EMF
JSON line on stdout, which the ECS `awslogs` driver already ships to
CloudWatch Logs — no agent, no SDK, no metric filter. The hot path only bumps
an in-memory counter or histogram bucket, so a few thousand requests per
second cost one log line per flush, not per request.

| Variable | Default | Purpose |
| --- | --- | --- |
| `METRICS_ENABLED` | `false` | Master switch. Off by default so local runs and tests stay quiet; deployments set it to `true`. |
| `METRICS_NAMESPACE` | `Portunus` | CloudWatch namespace. |
| `METRICS_FLUSH_INTERVAL_SECONDS` | `60` | Flush period. Below CloudWatch's 60s storage resolution it costs log volume for no extra detail. |
| `METRICS_SERVICE_NAME` | `portunus` | Value of the `ServiceName` dimension (e.g. the proxy deployment's name). |

Dimensions are `ServiceName` and `Role` (from `GRPC_ROLE`) only — deliberately
low cardinality. A per-task or per-principal dimension would multiply the
custom-metric bill by the size of the fleet and of the customer base.

| Metric | Unit | Meaning |
| --- | --- | --- |
| `CheckAllowed` / `CheckDenied` | Count | ext_authz outcomes; together they partition every `Check`. |
| `CheckShed` | Count | Subset of `CheckDenied` returned as 503 (full-auth capacity exhausted). |
| `CheckError` | Count | Subset of `CheckDenied` returned as another 5xx (500 internal, 504 auth timeout). |
| `CheckLatency` | Milliseconds | Distribution of end-to-end `Check` duration. |
| `AuthCacheRedisHit` / `AuthCacheRedisMiss` / `AuthCacheRedisError` | Count | Redis auth-cache outcomes on the in-process cache miss path. |
| `FullAuth` / `FullAuthLatency` | Count / Milliseconds | Full authentications (STS `get-caller-identity` + Secrets Manager) and their duration, timed on failure as well as success. |
| `FullAuthShed` | Count | Full authentications refused by the concurrency semaphore. |
| `DroppedRecords` / `DeliveryFailedRecords` | Count | Audit records the publish queue refused (full, over its byte budget, or stopping), and records Kinesis did not accept after retries. |
| `KinesisThrottledRecords` | Count | Audit records rejected for Kinesis quota reasons. |
| `KinesisPutErrors` | Count | Audit records in a `PutRecords` attempt that failed for any other reason: a non-throttling `ErrorCode`, a response that cannot confirm which records succeeded, or the call raising. Counted per attempt, so a record the retry delivers still counts once. |
| `PublishQueueDepth` | Count | Publish-queue occupancy sampled at flush. |
| `EventLoopLag` | Milliseconds | Drift of a 1s sleep — the loop's scheduling backlog, which separates "Portunus is CPU-starved" from "the dependency is slow". |

Counters are reported as **per-interval deltas**, so a CloudWatch `Sum` over
any period is that period's true count regardless of task restarts.
Distributions ship as EMF `Values`/`Counts` arrays over a √2-spaced bucket
ladder; each bucket reports its upper bound, so a latency is never
under-reported (over-reported by at most ~41%) and CloudWatch can still
compute averages and percentiles. In a split `GRPC_ROLE` deployment each
process registers only the metrics it owns, so neither role dilutes the
other's series with structural zeroes.

## gRPC publisher tuning

The gRPC publisher accepts these optional settings:

| Environment variable | Default | Allowed range |
| --- | --- | --- |
| `GRPC_PUBLISH_WORKERS` | 1 | 1–64 |
| `GRPC_PUBLISH_BATCH_SIZE` | 3000 records | 1–3000 |
| `GRPC_PUBLISH_COALESCE_MS` | 5 milliseconds | 0–100, finite |

The defaults are the load-tested settings: with them one pod sustained 600 RPS
with exact audit, while much smaller batches send about one record per
`PutRecords` call and collapse to roughly 100 RPS under load.

The batch size groups queued records across destinations. Each stream's records
are packed into Kinesis records of up to 256 KiB / 500 audit records, and
`PutRecords` calls obey the 500-record and 5-MiB limits. Coalescing pauses between
partial batches, adding up to the configured delay for new arrivals.
Queue record and payload-byte limits continue to apply.


## Tests

Unit tests live in `portunus/tests/` and run without Docker:

```bash
cd portunus && uv run pytest -q
```

Coverage includes both gRPC servicers in isolation (with `Fake*` collaborators rather than `MagicMock`, so assertions can read the data flowing through), the publish queue, the in-process and Redis caches, token minting, frame parsing, and a schema-consistency check that guards the Glue ETL contract.

Behaviour and end-to-end tests live at the repo root in `tests/` and require `docker compose up --build --wait`; see the [root README](../README.md#running-tests).

## Running the service locally

The intended entry point is the full stack (`docker compose up --build` at the repo root), which brings up Envoy, Redis, LocalStack, and an httpbun upstream alongside Portunus. That is the only way to exercise a request end to end, since the auth and audit surfaces are Envoy filter callouts rather than routes you can curl.

To run the servicer process on its own, first configure the AWS region, Redis, `GRPC_ENABLED=true`, and a `GRPC_PROXY_API_KEY` of at least 16 bytes. All seven metadata/request/response `KINESIS_*_STREAM` settings are required (except with `GRPC_ROLE=auth`); `KINESIS_WS_SUMMARY_STREAM` is optional. Then run from the repo root:

```bash
uv sync
uv run python -m portunus.grpc.server
```

That is the same entry point the container uses (`CMD ["python", "-m", "portunus.grpc.server"]`, also exposed as the `portunus-server` script). It serves ext_authz, ext_proc, `grpc.health.v1.Health` and reflection on `GRPC_PORT`; reflection means a client needs no local `.proto` copy. For logic changes, the unit tests are faster than a live process:

```bash
uv run pytest portunus/tests
```

### Audit overload handling

Set `GRPC_AUDIT_PORT` to a port different from `GRPC_PORT` to run authentication
and audit on separate gRPC server instances. Both use `GRPC_HOST` and validate
the proxy identity; auth remains on `GRPC_PORT`, and both ports serve the
health service. Configure the proxy to send audit traffic to the matching port;
its `/healthz` then requires both ports to be `SERVING`. Leaving it unset
retains the shared listener.

`GRPC_AUDIT_DROP_ON_PRESSURE=true` rejects audit submissions immediately once
the bounded queue fills. Body byte/count limits and reserved metadata space
still apply, but metadata records can also be lost when that reserve fills.
A dropped body chunk leaves a gap in its body's `chunk_id` sequence; every
rejected record is counted in `dropped_total` (the `DroppedRecords` metric).
The default is false, retaining bounded waits for metadata admission.

Kinesis record-level failures receive one retry, under fresh partition keys, after an asynchronous jittered
backoff. Repeated body-drop warnings are limited to one per second per servicer;
loss counters still include every rejected record. Separate server admission
shares the same Python process and CPU; this is best-effort audit delivery,
with authentication remaining fail closed.
