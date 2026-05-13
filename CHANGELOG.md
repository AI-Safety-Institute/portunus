# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `envoy.filters.http.ext_authz` + `envoy.filters.http.ext_proc` gRPC
  pipeline replacing the previous Lua-driven REST callouts. Auth runs
  synchronously via `PortunusAuthServicer.Check`; body / header audit
  runs over `FULL_DUPLEX_STREAMED` via `PortunusProcessServicer.Process`.
- `GRPC_ENABLED` / `GRPC_PORT` env vars to opt into the new server (off
  by default).
- `KINESIS_WS_SUMMARY_STREAM` env var + `WSSummaryRecord` model: one
  record per WebSocket connection with per-direction frame counts and
  close code, joinable on `request_id`.
- `x-portunus-proxy-key` gRPC `initial_metadata` identity check on
  both Check and Process; `x-portunus-target-host` is sourced from the
  same channel (not the HTTP request) to close a host-validation
  forgery vector.

### Changed
- Request signing (Content-Digest + RFC 9421 Signature/Signature-Input)
  reimplemented in the ext_authz path. Envoy's ext_authz filter buffers
  the request body via `with_request_body` (capped at 1 MiB) and ships
  it to the Check service alongside the headers; tenants with a
  `signing_key` get Content-Digest computed over the body and the
  signature headers added before the request reaches upstream.
  Signing-disabled tenants see no change in latency beyond the buffer
  cost. Replaces the legacy Lua filter that performed the same work
  inline.
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
- Denied auth responses are JSON (`{"error": {"message": ..., "request_id": ...}}`)
  with `content-type: application/json`, `x-{prefix}-error: true`, and
  `x-portunus-debug-id`. Header prefix is `PORTUNUS_HEADER_PREFIX`.

### Removed
- Legacy REST `/authorise` and `/log/*` routes and their Lua-side
  proxy-utils library. Same audit + signing surface now flows through
  the gRPC services.

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