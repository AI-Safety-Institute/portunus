# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.5.1]

### Security
- Don't interpolate boto3/Kinesis exceptions or raw payloads into error
  logs (`relay/handler.py`, `relay/logger.py`, `models.py`). The payload
  is a Bearer-stripped base64 blob containing temporary AWS credentials;
  Kinesis exceptions can echo the request body.
- Drop the upstream URI from the `Upstream connected …` log line; some
  upstreams put short-lived tokens in the query string.

### Added
- Upstream WebSocket close code is now captured, logged, and forwarded
  to the client. The relay used to substitute `1000 NORMAL` on every
  upstream-initiated close, hiding upstream errors and confusing
  clients (notably codex's retry path).
- `WS_AUTH_TIMEOUT` env var (default 5s) bounds the auth phase. Without
  it a hung STS/Secrets Manager region or a stalled client could pin a
  `max_connections` slot for botocore's ~60s default.
- `ws-echo` now mocks the OpenAI Responses API on `/v1/responses`
  (other paths still echo). Useful for pointing codex at staging.
  Configurable via `RESPONSE_CHUNKS` / `CHUNK_INTERVAL_SEC`.

### Fixed
- Per-connection summary Kinesis record (`x-ws-type=websocket-summary`)
  survives mid-relay cancellation; previously dropped when uvicorn
  cancelled the route during shutdown.

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

[0.5.1]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/UKGovernmentBEIS/portunus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/UKGovernmentBEIS/portunus/releases/tag/v0.1.0