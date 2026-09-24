# Portunus

## Overview

This repo implements a secure API key proxy with two cooperating components:

- **Proxy**: Envoy-based reverse proxy whose filter chain delegates auth and audit to Portunus over gRPC.
- **Portunus**: gRPC server hosting two servicers (Envoy ext_authz `Check` and ext_proc `Process`) plus the standard gRPC health service. Manages API keys from Secrets Manager, Redis-cached auth state, and Firehose publication.

## Key functionality

- Securely retrieve API keys from AWS Secrets Manager via short-lived AWS credentials supplied in the client's request.
- Transparently proxy requests to third-party APIs (e.g. OpenAI, Anthropic) with header substitution.
- Stream request / response / WebSocket audit to Firehose (direct-PUT) for downstream archival and analysis.
- Redis cache for authorisation responses to keep the hot path off Secrets Manager.
- Optional RFC 9421 request signing for Anthropic-style upstreams (Content-Digest + Signature / Signature-Input).
- TLS termination, per-route rate limiting, and request-id propagation throughout.

## Detailed request flow

### Authentication (ext_authz)

1. Client sends a request with `Authorization: Bearer <base64-encoded payload>` where the payload is
   `base64(json({"credentials": {…AWS STS creds}, "secret_arn": "arn:aws:secretsmanager:…"}))`.
2. Envoy invokes the ext_authz `Check` filter on headers only — no body buffering.
3. Portunus's `PortunusAuthServicer.Check` (in `portunus/portunus/grpc/auth_servicer.py`):
   - Validates the gRPC `initial_metadata` `x-portunus-proxy-key` (Envoy-side identity).
   - Reads `x-portunus-target-host` from the same channel (not the HTTP request) to avoid client-side host forgery.
   - Checks the in-process L1 cache (`services/local_auth_cache.py`, short TTL, single-flight per key), then the Redis cache; on hit, returns the cached api_key. The key is the `sha256` of the **independently hashed** `target_host` and `payload` digests (`sha256(sha256(host) || sha256(payload))`, no delimiter, host normalised as on the miss path). The `target_host` binding is load-bearing: without it a bearer authorised for provider A could reuse a cached api_key through a proxy fronting provider B, bypassing the host restriction `validate_and_extract_api_key` enforces on miss. Hashing the two components separately rather than joining them means no `(host, payload)` pair can collide by shifting bytes across a separator.
   - On miss: decodes the payload, builds an STS session, calls `get-caller-identity`, fetches the secret from Secrets Manager, validates the target host if the secret is JSON-shaped, and caches the result.
   - Forwards `principal_info` / `secret_arn` to ext_proc via `CheckResponse.dynamic_metadata`; ext_proc owns the Firehose metadata publish off the auth path.
   - Returns header mutations: the real `Authorization` header (api_key from the secret), the prefix-stripped payload, and (for signing tenants) the request header `x-portunus-signing-required: true`. On the non-signing branch `_ok` adds the header to `headers_to_remove` so a client-supplied value is stripped; on the signing branch it uses `OVERWRITE_IF_EXISTS_OR_ADD` to replace any client-supplied value with `true`. Envoy applies `headers_to_add` before `headers_to_remove`, so listing the header in both would strip the value we just set. Either way, the route_config also strips `x-portunus-signing-required` inbound — defence in depth.

### Signing (composite filter dispatching a second ext_authz pass)

For tenants whose secret carries a `signing_key` block:

1. A **composite filter** in envoy.yaml matches the request header `x-portunus-signing-required: true` set by the first `Check` (via `HttpRequestHeaderMatchInput`, not dynamic_metadata — no `HttpRequestMetadataMatchInput` exists in the pinned Envoy 1.38.x).
2. It dispatches a **second `ext_authz` filter** that has `with_request_body` set. The body is buffered (up to 32 MiB, matching Anthropic's documented request-body ceiling). `allow_partial_message: false` — Envoy returns 413 rather than silently truncate.
3. The same servicer re-authenticates (cache hit in prod), computes `Content-Digest` over the buffered body, and signs via KMS using the user's STS credentials. `KMS.Sign` is sync `boto3` offloaded via a dedicated bounded executor so the gRPC.aio event loop stays free.
4. Returns `Content-Digest`, `Signature`, and `Signature-Input` as header mutations.

Unsigned tenants never enter the buffering path; the body streams end-to-end.

### Observability (ext_proc)

1. Envoy streams request and response bodies — and post-101 WebSocket frames — to `PortunusProcessServicer.Process` in `portunus/portunus/grpc/proc_servicer.py`.
2. Body mode is `STREAMED` with `observability_mode: true` — Envoy ignores every `ProcessingResponse`, so the servicer is fire-and-forget from the customer's data path. Note: `observability_mode` only supports body modes `NONE` and `STREAMED` — `FULL_DUPLEX_STREAMED` is silently rejected at runtime.
3. Each body chunk is published to Firehose as its own record with a monotonic per-direction `chunk_id` and `num_chunks=0` sentinel; consumers reassemble by `request_id` and check completion/loss markers.
4. WebSocket frames are parsed with `wsproto` (PerMessageDeflate finalize()'d against the upstream's `Sec-WebSocket-Extensions`). Each frame is a body record; one `WSSummaryRecord` per connection carries frame counts and close code.

## Configuration

### Environment variables (selected)

| Variable | Purpose | Notes |
|---|---|---|
| `AWS_REGION` | All AWS clients | required |
| `API_KEY_HEADER` | Header name carrying the payload | default `authorization` |
| `API_KEY_PREFIX` | Prefix on the value | default `Bearer ` |
| `PORTUNUS_HEADER_PREFIX` | Prefix for response headers (`x-{prefix}-error`, `x-{prefix}-ping`; `x-portunus-debug-id` is fixed) | default `portunus` |
| `GRPC_ENABLED` / `GRPC_PORT` | Enable / port for the ext_authz + ext_proc server | must be enabled for this image; default off |
| `GRPC_AUDIT_PORT` / `GRPC_ROLE` | Separate ext_proc listener; which servicers this process hosts (`all` / `auth` / `audit`) | run one `auth` and one `audit` process to keep audit load off the auth event loop; see `proxy/README.md` |
| `GRPC_HOST` | Interface the gRPC server binds to | loopback by default; set `0.0.0.0` if Envoy and Portunus are in separate netns |
| `GRPC_PROXY_API_KEY` | Pre-shared key for the Envoy → Portunus gRPC channel (Envoy presents it as `x-portunus-proxy-key` initial_metadata; proxy side sets the same value via `PORTUNUS_API_KEY`) | identity check on both servicers |
| `CACHE_DURATION` | Auth-cache TTL | seconds |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_MAX_CONNECTIONS` | Redis connection | |
| `REDIS_POOL_TIMEOUT_SECONDS` / `REDIS_HEALTH_CHECK_INTERVAL_SECONDS` | Blocking-pool wait at the `REDIS_MAX_CONNECTIONS` cap; idle-connection PING interval | defaults `1.0` / `30`. The pool queues bursts rather than failing them over to STS |
| `AUTH_LOCAL_CACHE_TTL_SECONDS` / `AUTH_LOCAL_CACHE_STALE_SECONDS` / `AUTH_LOCAL_CACHE_MAX_ENTRIES` | In-process (L1) auth cache in front of Redis: TTL, stale-on-Redis-failure window, LRU bound | defaults `30` / `300` / `10000`; TTL `0` disables. Revocation takes up to the TTL per task (plus the stale window during a Redis outage), never past credential expiry |
| `AUTH_FALLBACK_MAX_CONCURRENT` / `AUTH_FALLBACK_ACQUIRE_TIMEOUT_S` | Cap on concurrent full authentications (STS + Secrets Manager) per process; requests that can't get a slot within the timeout are shed with 503 | defaults `32` / `1.0`. Stops a Redis outage turning into an STS/Secrets Manager stampede |
| `FIREHOSE_*_STREAM` | Per-record-type Firehose delivery streams (metadata, request/response headers/body/trailers, ws summary) | direct-PUT |
| `RATE_LIMIT_PERCENT_ENABLED` / `RATE_LIMIT_INTERVAL_SECONDS` / `RATE_LIMIT_REQUESTS_PER_INTERVAL` | Optional rate limiting | `0` disables |
| `METRICS_ENABLED` | Aggregate and emit CloudWatch EMF metrics on stdout | default `false`, so local runs and tests stay quiet; the task definition sets it |
| `METRICS_NAMESPACE` / `METRICS_SERVICE_NAME` | CloudWatch namespace, and the `ServiceName` dimension value | defaults `Portunus` / `portunus`. Dimensions are `ServiceName` + `Role` (from `GRPC_ROLE`) only — nothing per-task, per-principal or per-host |
| `METRICS_FLUSH_INTERVAL_SECONDS` / `METRICS_EVENT_LOOP_PROBE_SECONDS` | Flush period for the aggregated interval; sampling period of the event-loop lag probe | defaults `60` / `1.0`. Counters ship as per-interval deltas and latencies as EMF `Values`/`Counts` histograms, so the hot path costs one counter bump per request, not one log line |

## Observability

No distributed tracing. Per-request correlation is `x-request-id` (Envoy
access log → Portunus structured logs → Firehose audit records), plus an
inbound `x-amzn-trace-id` `Root=` id on log lines when an upstream set one.
Aggregate behaviour is CloudWatch EMF: `portunus/portunus/metrics.py` keeps
counters, delta sources, gauges and bucketed distributions in memory and
`grpc/server.py`'s reporter flushes one `_aws` JSON line per interval, with a
final flush at drain. Metric names are constants in `metrics.py` — use them
rather than string literals, since a typo'd name just never appears.

## Development

```bash
uv sync                                # install deps (root workspace + portunus package)
uv run pytest portunus/tests           # unit tests, fast, no Docker
docker compose up --build --wait       # bring up the stack
uv run pytest tests/                   # behaviour + e2e tests through the stack
```

CI runs both lanes (`.github/workflows/ci.yml`); lint and type-check skip the Docker-driven tests.

## Important files

- `/portunus/portunus/grpc/server.py` — gRPC server lifecycle: health, reflection, drain.
- `/portunus/portunus/grpc/auth_servicer.py` — ext_authz `Check` implementation; auth + signing.
- `/portunus/portunus/grpc/proc_servicer.py` — ext_proc `Process` implementation; HTTP body and WS frame audit.
- `/portunus/portunus/grpc/frame_observer.py` — wsproto-driven WS frame parsing.
- `/portunus/portunus/services/publish_queue.py` — bounded async queue with headroom for metadata vs body submits.
- `/portunus/portunus/services/auth_service.py` — STS + Secrets Manager + cache orchestration.
- `/portunus/portunus/services/secrets_service.py` — Secrets Manager fetch (boto session injectable for tests).
- `/portunus/portunus/services/signing_service.py` — RFC 9421 signing via KMS.
- `/portunus/portunus/services/publish_service.py` — Firehose direct-PUT publishing.
- `/portunus/portunus/models.py` — Pydantic + dataclass models; ships standalone to Glue (lazy imports of other portunus modules).
- `/proxy/envoy.yaml` — Envoy configuration: listener, filter chain, ext_authz / ext_proc clusters, routes.
- `/proxy/entrypoint.sh` — TLS config and `envsubst` for environment variables.

## Testing commands

```bash
# Unit tests (fast, in-CI)
cd portunus && uv run pytest -q

# Full behaviour + e2e (slow, docker-compose required)
docker compose up --build --wait
uv run pytest tests/ -q
```
