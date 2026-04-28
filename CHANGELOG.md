# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- Graceful WebSocket drain on shutdown. Active relay tasks are now
  given `drain_timeout` seconds to finish on their own — an in-flight
  LLM response streaming through the relay will complete at its natural
  `response.completed` boundary instead of being cut short by an
  immediate `task.cancel()`. Only tasks still holding an open socket
  after the deadline are force-cancelled, and their cleanup path then
  has up to `force_close_timeout` seconds to send the 1001 GOING_AWAY
  close frame and publish the summary record.
- `WS_DRAIN_TIMEOUT` default raised from 10s to 25s. Operators
  deploying Portunus must ensure their container `stop_timeout` is
  set high enough to cover `drain_timeout + force_close_timeout +
  log_queue_stop_timeout` (default totals 40s).
- `WS_FORCE_CLOSE_TIMEOUT` (new, default 5s) — grace period for
  force-cancelled relays to flush their close frame and summary.
- `WS_LOG_QUEUE_STOP_TIMEOUT` (new, default 10s) — bounds how long
  shutdown waits for the log queue to drain so a wedged Kinesis
  worker cannot hang the whole shutdown until SIGKILL.
- Lifespan shutdown is now structured so each phase (WS drain, log
  queue stop, Redis client close) runs in its own try/finally; a
  failure in one phase no longer skips the next. Previously a
  `stop_log_queue` exception would silently leak Redis connections.
- `_relay` now guarantees that its inner `client_to_upstream` /
  `upstream_to_client` tasks are cancelled and awaited in a `finally`
  block, so an outer cancel (e.g. during shutdown) can never orphan
  them against a closing socket.

### Migration

- Container `stop_timeout` (`ecs.ContainerDefinition.stop_timeout` or
  `docker stop -t`) must allow at least 40s for the new defaults to
  drain cleanly. AISI's deployment at `AI-Safety-Institute/api-key-proxy`
  sets 90s on both the Portunus backend and Envoy containers, with
  `WS_DRAIN_TIMEOUT=60`. Other deployments using the previous 10s
  drain default should bump their `stop_timeout` to ≥40s before
  upgrading; otherwise the longer drain will be SIGKILLed mid-flush
  and the new behaviour is no better than the old.

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