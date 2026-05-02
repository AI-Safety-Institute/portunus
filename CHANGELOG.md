# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Security
- Stop leaking user content into CloudWatch via boto3 / Kinesis exception
  messages. `str(e)` for these exceptions can include the request body
  (i.e. the prompt being relayed), so the relay log paths now interpolate
  `type(e).__name__` only. Affects `relay/handler.py`, `relay/logger.py`.
- `PayloadError` no longer interpolates the raw post-Bearer base64 payload
  into its message — that blob contains AWS credentials and the error
  reaches CloudWatch via the auth path.
- Drop the upstream URI from the `Upstream connected to …` log line.
  Some upstreams put short-lived auth tokens in the query string; the
  log now uses `host:port/path` only.

### Added
- `WS_AUTH_TIMEOUT` env var (default 5s) bounds the auth phase of every
  new WS upgrade. botocore defaults each AssumeRole / GetSecretValue
  call to ~60s, which let a hung region — or a client that opens TCP
  but never sends an Authorization header — pin a `max_connections`
  slot for the full default. Connections that exceed the cap close
  with code 4001 and reason `"Auth timeout"`.
- `ws-echo` now also speaks just enough of the OpenAI Responses API
  WebSocket protocol on `/v1/responses` to drive a multi-turn codex
  client through the relay during staging tests. Anything else still
  echoes literally, so existing k6 scripts hitting `/echo` are
  unchanged. Configurable via `RESPONSE_CHUNKS` / `CHUNK_INTERVAL_SEC`
  env vars.

### Fixed
- Per-connection summary log (`x-ws-type=websocket-summary` Kinesis
  record) survives a mid-relay cancellation. Previously, when uvicorn
  signalled a shutdown via cancel, the summary publish was skipped
  and the session disappeared from Kinesis accounting. The relay now
  shields the summary publish in a `finally` block.
- The relay now forwards the upstream's WebSocket close code to the
  client instead of substituting `1000 NORMAL` on every
  upstream-initiated close. This lets clients distinguish a clean
  completion from an upstream provider error (e.g. 1011 INTERNAL_ERROR,
  1013 TRY_AGAIN_LATER, 1009 MESSAGE_TOO_BIG) and gives operators the
  diagnostic signal they need in the per-connection log line, which
  now includes `code=…` and `reason=…`.
- Disable websockets-library keepalive pings on the upstream connect
  (`ping_interval=None`). LLM upstreams (OpenAI Responses API in
  particular) can spend tens of seconds on a single reasoning step
  without sending application bytes; the library's default 20s
  ping_timeout was closing the upstream connection with code 1011
  during reasoning, which the relay then forwarded as a mid-stream
  close to the codex client. Codex's retry path (one suppressed +
  visible `Reconnecting... 2/5`, `3/5`, `4/5`) made this look like
  flaky upstreams when it was actually our own keepalive timing out.
  The bidirectional relay loop still detects a dead upstream via the
  recv iterator returning, and `max_connection_lifetime` bounds the
  worst-case silent-dead-peer at 55 minutes.

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