# Portunus

## Overview

This repo implements a secure API key proxy with two cooperating components:

- **Proxy**: Envoy-based reverse proxy whose filter chain delegates auth and audit to Portunus over gRPC.
- **Portunus**: gRPC server hosting two servicers (Envoy ext_authz `Check` and ext_proc `Process`) plus the standard gRPC health and reflection services. Resolves API keys from Secrets Manager (or mints short-lived tokens), caches auth results in process and in Redis, and publishes audit records to Kinesis Data Streams.

## Key functionality

- Securely retrieve API keys from AWS Secrets Manager via short-lived AWS credentials supplied in the client's request, or mint a short-lived provider token through a federation role (`*_wif` secret types).
- Transparently proxy requests to third-party APIs (e.g. OpenAI, Anthropic) with header substitution.
- Stream request / response / WebSocket audit to Kinesis Data Streams (records packed newline-delimited, random partition keys), each drained by a Firehose that deaggregates to S3.
- In-process (L1) and Redis caches for authorisation results to keep the hot path off STS and Secrets Manager.
- TLS termination, rate limiting, and request-id propagation throughout.

## Detailed request flow

### Authentication (ext_authz)

1. Client sends a request with `Authorization: Bearer <base64-encoded payload>` (`API_KEY_HEADER` / `API_KEY_PREFIX`), where the payload is
   `base64(json({"credentials": {…AWS STS creds}, "expiration": "...", "secret_arn": "arn:aws:secretsmanager:…"}))`.
   - Generate one with the `portunus encode-credentials <secret-arn> [--policy <file-or-json>]` CLI (`cli.py`), which assumes the caller's role with a scoped-down session policy and encodes the temporary credentials, or programmatically with `encode_payload(credentials, secret_arn)` in `services/payload_service.py`.
2. Envoy invokes the ext_authz `Check` filter on headers only. The body is never sent, so requests stream end to end.
3. Portunus's `PortunusAuthServicer.Check` (in `portunus/portunus/grpc/auth_servicer.py`):
   - Validates the gRPC `initial_metadata` `x-portunus-proxy-key` (Envoy-side identity) against `GRPC_PROXY_API_KEY`.
   - Takes the target host from the route's `context_extensions` (the WebSocket route sets `WS_TARGET_HOST`) or the `x-portunus-target-host` initial metadata, never from the HTTP request; the route_config strips client-supplied `x-portunus-*` control headers.
   - Calls `AuthService.authenticate` (`services/auth_service.py`) under a 9 s budget (`_AUTH_TIMEOUT_S`; 504 when exceeded). Envoy's ext_authz timeout is 10 s.
4. `AuthService.authenticate`:
   - Checks the in-process L1 cache (`services/local_auth_cache.py`, short TTL, single-flight per key), then Redis. The key is `auth_cache_key(payload, target_host)` in `services/cache_service.py` (`sha256(f"{payload}\n{target_host or ''}")`, the formula Portunus has always used, shared by L1 and Redis). The `target_host` binding is load-bearing: a cached result must only be reused for the upstream it was authorised for, matching the host restriction enforced on a miss.
   - On a miss, takes one of `AUTH_FALLBACK_MAX_CONCURRENT` full-auth slots (shed with 503 after `AUTH_FALLBACK_ACQUIRE_TIMEOUT_S`), decodes the payload, builds an STS session, calls `get-caller-identity`, fetches the secret from Secrets Manager and parses it (`services.secret_validation_service.parse_secret`): plaintext or `{"secret", "host"}` is a stored key; `{"type": "anthropic_wif", ...}`, `{"type": "openai_wif", ...}`, `{"type": "openrouter_wif", ...}` or `{"type": "gcp_wif", ...}` describes a token to mint. Host restrictions are an exact string comparison against the secret's `host`.
   - For mint secrets, `services.federation_service.TokenMintService` checks the federation role ARN is in `FEDERATION_ALLOWED_ACCOUNT_IDS` and under `FEDERATION_ROLE_PATH_PREFIX` (any path depth) and assumes exactly that role with the caller's credentials (regional STS endpoint). `anthropic_wif`: issues an STS web identity token from that session and exchanges it at `https://api.anthropic.com/v1/oauth/token`. `openai_wif`: issues an ES384-signed STS web identity token and exchanges it at `https://auth.openai.com/oauth/token` (RFC 8693 token exchange with the secret's `identity_provider_id` and `service_account_id`). `openrouter_wif`: issues a 15-minute RS256-signed STS web identity token and exchanges it at `https://openrouter.ai/api/v1/oauth/token` (RFC 8693 token exchange, form-encoded, with the secret's `federation_policy_id`). `gcp_wif`: issues an RS256-signed STS web identity token for the pool provider named by the secret's `audience`, exchanges it at Google STS (RFC 8693 token exchange, the JWT as an OIDC subject token) for a federated token and impersonates the service account through the IAM Credentials API. Either way the result carries `output_header="authorization"`, `output_prefix="Bearer "`. Every mint logs one INFO line pairing the identity token's `jti` with the role, user, principal, session and project; the token is never logged. Concurrent misses for one payload and target share a mint per process. STS or provider unavailability, or a missed 6 s mint deadline, raises `UpstreamServiceError` (503).
   - Caches the result in Redis and L1 for `_cache_ttl()`: the earliest of `CACHE_DURATION`, the caller's credential expiry and, for minted tokens, one minute before the token expires. L1 serves an entry for `AUTH_LOCAL_CACHE_TTL_SECONDS`, never past that cap, and never after it expires (a Redis timeout then rejects; other Redis errors fall back to full authentication under the cap).
5. `Check` answers with header mutations: the credential is written to the result's `output_header` (else `API_KEY_HEADER`) with `output_prefix` (else `API_KEY_PREFIX`), and the inbound `API_KEY_HEADER` (which carries the caller's AWS credentials) is removed when it differs from that header; every other header is forwarded untouched. `dynamic_metadata` carries `upstream_auth_header`, `principal_info` and `secret_arn` to ext_proc, which publishes the audit metadata record off the auth path.
6. Denials return `{"error": {"message", "request_id"}}` with `x-{PORTUNUS_HEADER_PREFIX}-error: true` and `x-portunus-debug-id`. `PayloadError` / `CredentialsError` → 401, `AuthenticationError` → 403, `FetchSecretError` → its own status, `UpstreamServiceError` / `AuthOverloadedError` → 503, timeout → 504, anything else → a generic 500 (the exception type is logged, never its message).

### Observability (ext_proc)

1. Envoy streams request and response headers, bodies and trailers — and post-101 WebSocket frames — to `PortunusProcessServicer.Process` in `portunus/portunus/grpc/proc_servicer.py`.
2. Body mode is `STREAMED` with `observability_mode: true` and `failure_mode_allow: true` — Envoy ignores every `ProcessingResponse`, so the servicer is fire-and-forget from the customer's data path. Note: `observability_mode` only supports body modes `NONE` and `STREAMED` — `FULL_DUPLEX_STREAMED` is silently rejected at runtime.
3. Each body chunk is published as its own audit record with a monotonic per-direction `chunk_id` (`num_chunks=0` marks a streamed body); consumers reassemble by `request_id`. A streamed body is complete iff its `chunk_id`s are contiguous from 0 through the record with `final_chunk=true`.
4. WebSocket frames are parsed with `wsproto` (PerMessageDeflate finalize()'d against the upstream's `Sec-WebSocket-Extensions`). Each frame is a body record; one `WSSummaryRecord` per connection carries frame counts and close code (when `KINESIS_WS_SUMMARY_STREAM` is set).
5. Records go through a bounded queue (`services/publish_queue.py`) to `services/publish_service.py`, which packs them into ≤256 KiB / ≤500-record Kinesis records and sends `PutRecords` calls, retrying failed records once.

## Configuration

### Security model

Envoy reaches Portunus over gRPC and presents `PORTUNUS_API_KEY` as `x-portunus-proxy-key` initial metadata; both servicers reject calls whose key does not match `GRPC_PROXY_API_KEY` (at least 16 bytes; an empty key needs `GRPC_PROXY_API_KEY_OPTIONAL=true`, development only). `GRPC_HOST` defaults to loopback for the sidecar topology. The standard health and reflection services do not check the key, so keep the gRPC port reachable only by the proxy. Documented in README "Security model".

Audit captures full request/response bodies verbatim. Headers are captured in full except the credential headers (`_excluded_header_names` in `proc_servicer.py`): `KNOWN_AUTH_HEADERS` (backend setting, default `authorization,x-api-key,x-goog-api-key,api-key`, case-insensitive), `API_KEY_HEADER` and the header the upstream credential was written to (`upstream_auth_header` from dynamic metadata). No other redaction happens in Portunus; redaction/filtering/access-tiering of bodies is a downstream (ETL/query-layer) concern. Documented in README "Security model" → "Logged data".

### Environment variables (selected)

| Variable | Purpose | Notes |
|---|---|---|
| `AWS_DEFAULT_REGION` | All AWS clients (botocore), incl. the federation STS endpoint | required |
| `API_KEY_HEADER` | Header name carrying the payload (backend) | default `authorization` |
| `KNOWN_AUTH_HEADERS` | Credential headers left out of audit header capture (backend, comma-separated) | default `authorization,x-api-key,x-goog-api-key,api-key` |
| `API_KEY_PREFIX` | Prefix on the value (backend) | default `Bearer ` |
| `PORTUNUS_HEADER_PREFIX` | Prefix for response headers (`x-{prefix}-error`, `x-{prefix}-ping`, `x-{prefix}-rate-limit`; `x-portunus-debug-id` is fixed) | default `portunus`; read by both backend and proxy |
| `GRPC_ENABLED` / `GRPC_PORT` | Enable / port for the ext_authz + ext_proc server | must be enabled for this image; defaults off / `9000` |
| `GRPC_AUDIT_PORT` / `GRPC_ROLE` | Separate ext_proc listener; which servicers this process hosts (`all` / `auth` / `audit`) | run one `auth` and one `audit` process to keep audit load off the auth event loop; see `proxy/README.md` |
| `GRPC_HOST` | Interface the gRPC server binds to | default `127.0.0.1`; set `0.0.0.0` if Envoy and Portunus are in separate netns |
| `GRPC_PROXY_API_KEY` | Pre-shared key for the Envoy → Portunus gRPC channel (Envoy presents it as `x-portunus-proxy-key` initial_metadata; proxy side sets the same value via `PORTUNUS_API_KEY`) | identity check on both servicers |
| `CACHE_DURATION` | Upper bound on auth-cache TTL | seconds, default `86400` |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_MAX_CONNECTIONS` / `REDIS_USE_TLS` | Redis connection | defaults `localhost` / `6379` / – / `200` / `true` |
| `REDIS_POOL_TIMEOUT_SECONDS` / `REDIS_HEALTH_CHECK_INTERVAL_SECONDS` | Blocking-pool wait at the `REDIS_MAX_CONNECTIONS` cap; idle-connection PING interval | defaults `1.0` / `30`. The pool queues bursts rather than failing them over to STS |
| `AUTH_LOCAL_CACHE_TTL_SECONDS` / `AUTH_LOCAL_CACHE_MAX_ENTRIES` | In-process (L1) auth cache in front of Redis: TTL, LRU bound | defaults `30` / `10000`; TTL `0` disables. Revocation takes up to the TTL per task, never past credential expiry |
| `AUTH_FALLBACK_MAX_CONCURRENT` / `AUTH_FALLBACK_ACQUIRE_TIMEOUT_S` | Cap on concurrent full authentications (STS + Secrets Manager) per process; requests that can't get a slot within the timeout are shed with 503 | defaults `32` / `1.0`. Stops a Redis outage turning into an STS/Secrets Manager stampede |
| `FEDERATION_ALLOWED_ACCOUNT_IDS` | Comma-separated account IDs whose federation roles a mint secret may name | unset disables minting |
| `FEDERATION_ROLE_PATH_PREFIX` | IAM path federation role ARNs must start with | default `/portunus-fed/` |
| `FEDERATION_STS_ENDPOINT_URL` | STS endpoint for federation calls | default `AWS_ENDPOINT_URL`, else the regional endpoint |
| `KINESIS_*_STREAM` | Per-record-type Kinesis data streams (metadata, request/response headers/body/trailers; `KINESIS_WS_SUMMARY_STREAM` optional) | the seven non-summary streams are required unless `GRPC_ROLE=auth`; each stream feeds a Firehose with JSON RecordDeAggregation |
| `KINESIS_MAX_RECORD_SIZE` | Max bytes per audit record before chunking | default `1000000` |
| `RATE_LIMIT_PERCENT_ENABLED` / `RATE_LIMIT_INTERVAL_SECONDS` / `RATE_LIMIT_REQUESTS_PER_INTERVAL` | Optional rate limiting (proxy) | `0` disables; rate-limited requests get 429 with `x-{PORTUNUS_HEADER_PREFIX}-rate-limit: true` |
| `METRICS_ENABLED` | Aggregate and emit CloudWatch EMF metrics on stdout | default `false`, so local runs and tests stay quiet; the task definition sets it |
| `METRICS_NAMESPACE` / `METRICS_SERVICE_NAME` | CloudWatch namespace, and the `ServiceName` dimension value | defaults `Portunus` / `portunus`. Dimensions are `ServiceName` + `Role` (from `GRPC_ROLE`) only — nothing per-task, per-principal or per-host |
| `METRICS_FLUSH_INTERVAL_SECONDS` | Flush period for the aggregated interval | default `60`. Counters ship as per-interval deltas and latencies as EMF `Values`/`Counts` histograms, so the hot path costs one counter bump per request, not one log line |

## Observability

No distributed tracing. Per-request correlation is `x-request-id` (Envoy
access log → Portunus structured logs → audit records), plus an
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

CI (`.github/workflows/`) runs both lanes; lint and type-check skip the Docker-driven tests.

## Important files

- `/portunus/portunus/grpc/server.py` — gRPC server lifecycle: health, reflection, drain.
- `/portunus/portunus/grpc/auth_servicer.py` — ext_authz `Check` implementation.
- `/portunus/portunus/grpc/proc_servicer.py` — ext_proc `Process` implementation; HTTP body and WS frame audit, credential-header exclusion from header capture.
- `/portunus/portunus/grpc/frame_observer.py` — wsproto-driven WS frame parsing.
- `/portunus/portunus/grpc/proxy_auth.py` — proxy-key and target-host extraction from gRPC metadata.
- `/portunus/portunus/services/auth_service.py` — L1 → Redis → bounded full auth (STS + Secrets Manager) or mint; cache TTLs.
- `/portunus/portunus/services/local_auth_cache.py` — in-process L1 auth cache.
- `/portunus/portunus/services/cache_service.py` — Redis auth cache and the shared cache key (`auth_cache_key`).
- `/portunus/portunus/services/federation_service.py` — Short-lived upstream tokens: federation role assumption, the STS web identity token proof, one `exchange(proof, secret)` adapter per provider, and `TokenMintService._routes` pairing each secret type with its proof and adapter (a new provider adds a secret type, an adapter and one route).
- `/portunus/portunus/services/secret_validation_service.py` — Secret parsing (`parse_secret`) and target host validation.
- `/portunus/portunus/services/secrets_service.py` — Secrets Manager fetch (boto session injectable for tests).
- `/portunus/portunus/services/publish_queue.py` — bounded async queue with headroom for metadata vs body submits.
- `/portunus/portunus/services/publish_service.py` — packs audit records and publishes them to Kinesis Data Streams (`PutRecords`).
- `/portunus/portunus/models.py` — Pydantic + dataclass models; ships standalone to Glue (lazy imports of other portunus modules).
- `/portunus/portunus/config.py` — environment-driven configuration.
- `/proxy/envoy.yaml` — Envoy configuration: listener, filter chain, ext_authz / ext_proc clusters, routes.
- `/proxy/entrypoint.sh` — defaults, TLS config and `envsubst` for environment variables; SIGTERM drain.
- `/docs/federation-examples.md` — Per-provider walkthrough for the `*_wif` secret types: federation role as CloudFormation, lab registration, config secret, payload and request; a reference table.
- `/docs/runbooks/flush-auth-cache.md` — operator procedure for flushing the Redis auth cache.

## Testing commands

```bash
# Unit tests (fast, in-CI)
cd portunus && uv run pytest -q

# Full behaviour + e2e (slow, docker-compose required)
docker compose up --build --wait
uv run pytest tests/ -q
```
