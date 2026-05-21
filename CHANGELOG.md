# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.6.0]

### Changed
- Envoy WebSocket route now sets `max_stream_duration: 3300s` (55min) so
  scale-out can actually rebalance long-lived WS connections. Without
  this cap, a WS connection opened pre-scale-out stays pinned to its
  original task forever (LEAST_REQUEST only fires at connect time). 55min
  lets a 60min OpenAI Realtime session complete naturally while still
  cycling pathologically long sessions. HTTP / SSE traffic is unaffected
  (per-route). Close is TCP FIN → 1006 on the wire; SDK reconnect
  handles it.
- Envoy launched with `--drain-time-s 60 --drain-strategy gradual` for
  graceful shutdown. Default drain window (600s) exceeds ECS
  `stopTimeout` (max 120s), so without this Envoy gets SIGKILL'd
  mid-drain. Companion akp follow-up sets `stopTimeout=120s` on the
  envoy container and switches the ALB target group to
  `least_outstanding_requests`.
- Upstream provider cluster (`${TARGET_HOST}`): `lb_policy` changed
  `ROUND_ROBIN` → `LEAST_REQUEST`. Decorative under the current
  `LOGICAL_DNS` cluster type (one IP per connection), but aligned with
  intent for any future `STRICT_DNS` migration. Portunus cluster
  unchanged.

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