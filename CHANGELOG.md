# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- In-process auth-cache TTL cut from 500s to 10s (#94). `/cache/flush` reaches one
  task; the other tasks' in-process caches cannot be cleared remotely and
  converge only by TTL expiry — at 500s a flushed (e.g. compromised) key kept
  being served by most of the fleet for up to ~8 minutes. 10s bounds that
  window to ~10s while keeping the cache's hit-rate benefit.
  Cross-task invalidation is not implemented; TTL expiry remains the
  only bound.

## [0.6.0]

### Changed
- Bumped Envoy 1.31 → 1.38.3 (current supported release; keeps the proxy off the
  near-end-of-support 1.36 line). Required for reliable admin-driven connection
  draining: draining under in-flight async HTTP calls (the Lua audit `httpCall`s)
  could crash Envoy on shutdown — a teardown-crash class hardened across later
  releases — so we track a current version rather than pin an old one. (#90)
- Modernise dev tooling: ruff 0.15, mypy 2, pre-commit 4, websockets 16. (#86)

### Fixed
- Envoy now gracefully drains in-flight **plain-HTTP** streams on `SIGTERM`
  instead of exiting immediately and RSTing them, so ECS scale-in / deploys no
  longer cut streaming responses (SSE, AWS eventstream, slow LLM completions)
  mid-flight. `proxy/entrypoint.sh` orchestrates the drain through Envoy's
  loopback-only admin API (there is no YAML/config knob to drain on `SIGTERM`);
  bounded by `DRAIN_TIME_S` (default 60s). WebSocket sessions are unchanged —
  excluded from the drain and closed at drain end as they are today (WS-aware
  draining lands with the gRPC cutover, #19). For full effect it needs the
  companion api-key-proxy change raising the legacy fleet's `stop_timeout` and
  ALB `deregistration_delay` to 120s. (#90)
- Clear the in-process auth cache on `/cache/flush`, not just Redis. (#89)

### Security
- Bump Python deps to clear the security backlog (FastAPI/Starlette,
  cryptography). (#85)
- Pin the remaining build-time deps (uv image digest, yq checksum). (#87)
- Stop inheriting unnecessary secrets in CI workflows. (#88)

## [0.5.5]

### Changed
- Harden the supply chain: pin GitHub Actions, Docker base images, and Python
  dependencies by digest/hash, and enable Dependabot. (#31)

### Fixed
- Decode `Content-Encoding: br` (Brotli) response bodies. Previously fell
  through to UTF-8 decode on compressed bytes, marking the row as
  `response_body_decode_failure` and dropping it from token usage. (#26)

### Documentation
- Document the service-auth trust model and required deployment posture
  (proxy → Portunus authentication / network-isolation expectations). (#33)
- Document the audit-logging capture behaviour (what request/response data is
  captured; redaction is a downstream concern). (#37)

## [0.5.4]

### Fixed
- `_decompress_b64_body` now catches `zlib.error` in the gzip branch. A valid
  gzip header wrapping a corrupt deflate stream raises `zlib.error` (e.g.
  "invalid bit length repeat"), which escaped the existing
  `(OSError, EOFError)` handler and crashed the caller instead of marking the
  record as a decode failure — one such body in the 2026-06-11 00:00–12:00
  raw logs repeatedly killed whole `portunus-log-analysis-backfill` windows
  during the July 2026 regen. (#36)

## [0.5.3]

### Fixed
- Revert the dependency lock changes accidentally introduced by the #17 bulk
  lock regeneration (v0.5.1): restore both `uv.lock` files to the v0.5.0
  version set, and drop the `aws-xray-sdk` / `types-aws-xray-sdk` caps added
  alongside them. Among the accidental bumps, uvicorn 0.29.0 → 0.47.0 broke
  X-Ray trace propagation — uvicorn 0.47.0 imports the ASGI app before the
  serving event loop exists (encode/uvicorn#2919), so `AsyncContext()`
  (constructed at import time via `XRayService()`) binds to the wrong loop,
  `current_segment()` returns None in handlers, and every request logged
  `request_id="No-Trace-Id"`, collapsing all proxy logs into one group and
  OOMing the joined-logs ETL (2026-07-02 outage). The v0.5.2 aws-xray-sdk
  theory was wrong: the built image ran 2.14.0 in both the working and broken
  deployments.

### Added
- Constrain `uvicorn>=0.29.0,<0.47` so a future lock regeneration can't silently
  reintroduce the trace-breaking 0.47.0 (see the Fixed entry above); locked
  versions unchanged. (#28)
- `tests/test_trace_propagation.py`: boots a real uvicorn subprocess and asserts
  an `X-Amzn-Trace-Id` header round-trips into the handler's X-Ray segment
  (fails on uvicorn >=0.47; `TestClient` can't catch it). (#28)

## [0.5.2]

### Fixed
- Restore `aws-xray-sdk` to `>=2.15.0,<3`. v0.5.1 accidentally capped it to
  `<2.15` (an unrelated, undocumented rider in the #17 eventstream-decode change,
  `daf52c4`), which resolved the SDK *down* to 2.14.0 in downstream consumers.
  2.14.0 fails to propagate the X-Ray trace context in the proxy runtime, so
  every proxied request was logged with `request_id="No-Trace-Id"`; that
  collapsed all logs into a single request_id group and OOM-ed the downstream
  `portunus-log-analysis` Glue ETL, taking down joined-logs, token usage, and the
  misalignment-monitor dashboard for ~4 days (from 2026-07-02). Floored at
  2.15.0 so 2.14.0 can no longer resolve.

## [0.5.1]

### Fixed
- Decode AWS Bedrock `application/vnd.amazon.eventstream` response bodies into
  SSE so token usage is parseable for Bedrock streaming responses (previously
  stored undecoded and dropped downstream). (#17)
- Treat a truncated/incomplete eventstream as a decode failure rather than a
  silent partial, so cut-off Bedrock streams don't silently undercount tokens. (#24)

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

[0.5.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/UKGovernmentBEIS/portunus/releases/tag/v0.1.0