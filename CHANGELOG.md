# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Operator runbook for flushing the shared auth cache fleet-wide:
  `docs/runbooks/flush-auth-cache.md`. An operator runs
  `aws ecs execute-command` into a Portunus task and invokes the app's own
  `CacheService.flush_all()` (Redis `FLUSHDB`). This documents the
  replacement for the FastAPI `POST /cache/flush` endpoint retired in the
  0.6.0 gRPC cutover — the container ships the `redis` library but no
  `redis-cli` / `grpcurl`, and the single shared ElastiCache means one exec
  is fleet-wide. Requires ECS Exec on the Portunus service (akp #136).
- Audit-integrity sentinels on body records and WS summary records.
  Closes the gap where a publish-queue drop or a deflate-cap truncation
  was log-only — downstream ETL could reassemble incomplete bodies and
  treat them as complete.
  - `RequestBodyRecord` / `ResponseBodyRecord` gain `dropped: bool` and
    `truncated: bool` fields. When a body chunk is dropped under queue
    pressure, a sentinel body record (`body=""`, `body_size=0`,
    `dropped=True`, same `chunk_id`) is enqueued in its place so ETL
    sees an explicit marker rather than a silent chunk_id gap.
  - WS frames marked `truncated` by the deflate cap propagate that flag
    into the published body record (was set but never published).
  - `WSSummaryRecord` gains `dropped_client_frames` /
    `dropped_server_frames` / `truncated_client_frames` /
    `truncated_server_frames` as aggregate per-connection counters,
    joinable without scanning the body stream.
  - **Glue schema impact**: 2 new fields on request_body / response_body
    tables, 4 new fields on ws_summary. Backwards-compatible (all
    default `false` / `0`); akp ETL gets the new columns the next time
    it deploys.
- Bounded WebSocket connection lifetime via `route.max_stream_duration:
  3300s` on the WS route. WS connections that would otherwise stay
  pinned to a task across scale-out events now cycle every ~55 min,
  letting newly-scaled-out tasks pick up traffic. Caps WS only — HTTP
  / SSE routes are unaffected. Close is delivered as TCP FIN (1006
  Abnormal Closure on the wire); SDK reconnect handles it.
- Graceful proxy drain on `SIGTERM` via Envoy's
  `--drain-time-s 60 --drain-strategy gradual`. Replaces the default
  10-minute drain window which exceeded ECS `stopTimeout` and resulted
  in SIGKILL mid-drain. WS connections still close by TCP FIN (1006);
  injecting `1001 Going Away` would require a WASM filter, tracked as
  a follow-up.

### Changed
- `lb_policy` on the upstream provider clusters
  (`${TARGET_HOST}`, `ws_upstream`) is now `LEAST_REQUEST` rather than
  `ROUND_ROBIN`. With the current `LOGICAL_DNS` cluster type only one
  endpoint is resolved per connection so the change is decorative;
  future moves to `STRICT_DNS` (multivalue A records) will make it
  load-bearing.

### Fixed
- Firehose direct-PUT records are now newline-delimited so buffered S3
  objects remain parseable as JSON Lines.
- WebSocket summaries on normal stream close now use the non-droppable
  publish path so dropped/truncated frame counters are preserved.
- Auth backend calls now time out before Envoy's ext_authz deadline so
  callers receive Portunus's structured 504 response.
- The gRPC server receive/send message limit now has headroom above
  Envoy's 32 MiB signed-body cap.
- Root pytest discovery now includes `portunus/tests`, so CI collects
  the unit tests that cover the gRPC audit and auth services.
- WebSocket auth now validates host-restricted secrets against the WS
  upstream host when it differs from the HTTP upstream host.
- Oversized HTTP body chunks and WebSocket frame payloads are now split
  before publishing so individual Firehose records stay below the limit.
- Pre-101 WebSocket buffering now enforces the 256 KiB cap against the
  incoming chunk instead of allowing a single chunk to overshoot it.
- Removed the stale `CORS_ALLOWED_ORIGINS` proxy default left behind
  after CORS support was removed from the gRPC Envoy filter chain.

## [0.6.0]

### Added
- `envoy.filters.http.ext_authz` + `envoy.filters.http.ext_proc` gRPC
  pipeline replacing the previous Lua-driven REST callouts. Auth runs
  synchronously via `PortunusAuthServicer.Check`; body / header audit
  runs through `PortunusProcessServicer.Process` with
  `observability_mode: true` and body modes
  `request_body_mode / response_body_mode: STREAMED` — Envoy ignores
  every `ProcessingResponse` so the audit path is fire-and-forget from
  the customer's data path. `observability_mode` does not support
  `FULL_DUPLEX_STREAMED` (silently rejected at runtime); WS frames are
  observed via the `STREAMED` body mode through the upgraded stream.
- `GRPC_ENABLED` / `GRPC_PORT` env vars to opt into the new server (off
  by default).
- WebSocket audit via ext_proc: each observed WS frame is published as
  a body record and one `WSSummaryRecord` is emitted per connection
  with per-direction frame counts and close code, joinable on
  `request_id`. Frame parsing uses wsproto with a `PerMessageDeflate`
  extension that is explicitly `finalize()`d against the negotiated
  `Sec-WebSocket-Extensions` header on the upstream's 101 — otherwise
  the extension stays `_enabled=False` and wsproto rejects every RSV1
  (deflate) frame.
- `FIREHOSE_WS_SUMMARY_STREAM` env var + `WSSummaryRecord` model:
  populates the per-connection summary stream above.
- `x-portunus-proxy-key` gRPC `initial_metadata` identity check on
  both Check and Process; `x-portunus-target-host` is sourced from the
  same channel (not the HTTP request) to close a host-validation
  forgery vector.

### Changed
- Request signing (Content-Digest + RFC 9421 Signature/Signature-Input)
  reimplemented as a two-filter ext_authz chain:
  - **ext_authz #1** runs on headers only — no body buffering. On
    success it returns the upstream api_key as a header mutation and
    sets the request header `x-portunus-signing-required: true|false`
    (not `dynamic_metadata` — `HttpRequestMetadataMatchInput` doesn't
    exist in Envoy 1.36, so the composite filter matches via
    `HttpRequestHeaderMatchInput` instead). `_ok` always lists the
    header in `headers_to_remove` and the route_config also strips
    inbound copies — single source of truth, forgery-safe.
  - A **composite filter** matches on that header and conditionally
    invokes **ext_authz #2**, which has `with_request_body:
    max_request_bytes=33554432, allow_partial_message=false` (32 MiB,
    matching Anthropic's documented request-body ceiling; Envoy
    returns 413 rather than silently truncate). Pass #2
    re-authenticates against the Redis cache, computes Content-Digest
    over the buffered body, signs via KMS (sync `boto3` offloaded
    through `asyncio.to_thread` so the event loop stays free), and
    returns Content-Digest + Signature + Signature-Input as header
    mutations.

  Net: unsigned tenants stream end-to-end with no body buffering at any
  filter; signed tenants buffer only inside ext_authz #2. The pass is
  discriminated server-side by a `x-portunus-pass: signing` gRPC
  initial_metadata header set in envoy.yaml on the inner filter — same
  forgery-resistant channel used for `x-portunus-proxy-key` and
  `x-portunus-target-host`.
- HTTP body records now use a `chunk_id`-per-message wire format:
  each ext_proc body chunk lands as its own Kinesis record with a
  monotonic `chunk_id` per direction and `num_chunks=0` (sentinel:
  total derived at aggregation time). Aggregation happens in the
  akp Glue ETL — the same `reassemble_body_chunks` step that
  already handled multi-chunk bodies. The joined-log output
  consumed by aisitok is unchanged: one body record per direction
  with the concatenated payload. Streaming responses (Anthropic
  Messages, OpenAI SSE) now flow chunk-by-chunk through Kinesis
  rather than being held until end_of_stream.

  **Deploy ordering**: the matching akp Glue change (filter
  `num_chunks != 1`, total derived via `count_("*")`) MUST land
  before portunus releases that emit the `num_chunks=0` sentinel.
  Otherwise the legacy reassembly step drops every chunk past
  `chunk_id=0` and aisitok loses body bytes. Pin akp at a version
  carrying the Glue update before bumping the portunus image tag
  in prod.
- Denied auth responses are JSON (`{"error": {"message": ..., "request_id": ...}}`)
  with `content-type: application/json`, `x-{prefix}-error: true`, and
  `x-portunus-debug-id`. Header prefix is `PORTUNUS_HEADER_PREFIX`.
- Audit pipeline migrated from Kinesis Data Streams to Firehose direct-PUT.
  Portunus now publishes audit records straight to per-record-type
  Firehose delivery streams; Firehose still lands on S3 in the same
  Parquet shape, so **the akp Glue ETL is unchanged**.
  - Env vars renamed `KINESIS_*_STREAM` → `FIREHOSE_*_STREAM` (eight
    streams: metadata, request/response headers/body/trailers, ws
    summary). Also `KINESIS_MAX_RECORD_SIZE` →
    `FIREHOSE_MAX_RECORD_SIZE`. The akp companion PR provisions the
    new delivery streams and grants the task `firehose:PutRecord` /
    `firehose:PutRecordBatch`.
  - Publish path simplified to a single fire-and-forget `PutRecord`
    per audit event — the client-side `_StreamBatcher` (25-record /
    10ms coalescer), the partial-failure retry loop, and the
    `dropped_total` counter are gone. Firehose direct-PUT handles
    retry + DLQ server-side and removes the per-shard 1 MiB/s /
    1000 records/s ceiling that motivated client-side batching.
    Net: no more shard-hour cost, simpler client code, same S3
    destinations and partitioning, same Glue ETL.
  - **Quota dependency**: Firehose direct-PUT defaults are 5,000
    records/s and 5 MiB/s per account, 1,000 records/s or 1 MiB/s
    per delivery stream. Peak load is ~2,370 records/s/pod × 4 pods
    ÷ 8 streams = ~1,250/s on the busiest stream, just above the
    default. The quota increase is filed by the akp companion PR;
    portunus must not assume it's in place at deploy time.

### Removed
- Legacy REST `/authorise` and `/log/*` routes and their Lua-side
  proxy-utils library. Same audit + signing surface now flows through
  the gRPC services.
- Configurable CORS support (`CORS_ALLOWED_ORIGINS`) — the new Envoy
  filter chain has no CORS handling. No customer currently relies on
  this from a browser-origin SDK; will be reintroduced as an Envoy
  CORS filter if needed.
- WebSocket relay env vars: `WS_MAX_MESSAGE_SIZE`,
  `WS_MAX_CONNECTION_LIFETIME`, `WS_MAX_CONNECTIONS`,
  `WS_DRAIN_TIMEOUT`. Envoy owns the WS state machine now; these limits
  are configured directly in `envoy.yaml`.
- Proxy env vars: `PORTUNUS_API_KEY_HEADER`, `PORTUNUS_PORT`,
  `PORTUNUS_TRANSPORT_SOCKET`, `TARGET_HOST_USE_TLS`. Replaced by the
  TLS transport-socket vars (`TARGET_HOST_TRANSPORT_SOCKET`,
  `WS_TARGET_HOST_TRANSPORT_SOCKET`, `DOWNSTREAM_TLS_TRANSPORT_SOCKET`)
  and `PORTUNUS_GRPC_PORT`.

### Breaking — silent wire-shape deltas to know about
- **Denied-response body field rename**: `{"error": {..., "x_amzn_trace_id": ...}}`
  becomes `{"error": {..., "request_id": ...}}`. Clients programmatically
  scraping `x_amzn_trace_id` from Portunus auth-failure bodies will
  null out on cutover. Not aliased — the new name reflects what the
  value actually is.
- **Denied-response header rename**: `X-Amzn-Trace-Id` becomes
  `x-portunus-debug-id`. Same correlation value, different name.
  Telemetry / dashboards keyed on the old header lose attribution on
  auth failures.
- **Pre-shared key env var**: `GRPC_PROXY_API_KEY` (Portunus side) +
  `PORTUNUS_API_KEY` (proxy side) must be set to the same value in
  the same deployment revision. Mismatched rollout fails closed with
  401 on every request. `GRPC_PROXY_API_KEY_OPTIONAL=true` only for
  local dev.

## [0.5.0]

### Added
- `POST /cache/flush` endpoint that invalidates all cached auth responses
  via Redis `FLUSHDB`, for use when an API key is suspected compromised.
- Opt-in CORS support via `CORS_ALLOWED_ORIGINS`. Supports exact origins
  and wildcard suffix matching (e.g. `*.example.com`). Implemented in the
  Envoy Lua filter — handles OPTIONS preflight directly and adds
  `Access-Control-Allow-Origin` to proxied and error responses. When
  unset, behaviour is unchanged.

### Fixed
- Switch CI to `localstack/localstack:community-archive`; the default
  image now requires an auth token.

## [0.4.0]

### Changed
- WebSocket routing uses `Upgrade: websocket` header matching instead of
  `/ws/` path prefix. Clients can now upgrade on any path (e.g.,
  `/v1/responses`) without a special prefix.

## [0.3.0]

### Added
- WebSocket relay endpoint (`/ws/*`) with auth and per-message Kinesis logging.
- `ws-echo` echo server for load testing.

### Changed
- Lua filter now logs async errors instead of swallowing them.

## [0.2.0]

### Added
- `MetadataRecord.secret_arn` — Portunus now publishes the full AWS Secrets
  Manager ARN of the API key secret to Kinesis metadata records.

## [0.1.1] - 2026-02-26

### Added
- Release workflow: triggers on tag push (`v*`), creates GitHub release with
  auto-generated notes.
- `CONTRIBUTING.md` with release process documentation.
- Version derived from git tags via `hatch-vcs` (no hardcoded version in
  `pyproject.toml`).

## [0.1.0] - 2026-02-20

### Added
- Initial release of Portunus API key proxy.
- Envoy proxy with Lua filters for transparent credential swapping.
- FastAPI backend for authentication and API key retrieval from AWS Secrets
  Manager.
- Redis caching for API keys and STS credential validation.
- Kinesis logging for all proxied traffic (metadata, request/response
  headers and bodies).
- Pluggable backends (`AwsAuthBackend`, `DebugPublisher`) for secrets and
  log publishing.
- Full unit and integration test suite.
- ARN parsing utilities for principal identity extraction.

[Unreleased]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/UKGovernmentBEIS/portunus/releases/tag/v0.1.0
