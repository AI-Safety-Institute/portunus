# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.5.3]

### Fixed
- Pin `uvicorn>=0.29.0,<0.47` — the actual root cause of the 2026-07-02
  trace-id outage. v0.5.1's bulk lock regeneration bumped uvicorn
  0.29.0 → 0.47.0 in the package lock; uvicorn 0.47.0 eagerly imports the
  ASGI app in the parent process (encode/uvicorn#2919), before the serving
  event loop exists. `XRayService()` runs at import time and `AsyncContext()`
  binds its task factory to the loop present at construction, so under
  uvicorn >=0.47 X-Ray segments never propagate to request handlers:
  `current_segment()` returns None and every request logs
  `request_id="No-Trace-Id"`, collapsing all proxy logs into one group and
  OOMing the joined-logs ETL. Bisected and verified by A/B test against real
  uvicorn servers (0.46.0 traced, 0.47.0 broken); regression-guarded by
  `tests/test_trace_propagation.py`. Note: the aws-xray-sdk 2.14/2.15
  difference flagged in v0.5.2 was a red herring — the built image ran 2.14.0
  in both the working and broken deployments.
- Roll the package-level `portunus/uv.lock` (the lock the Docker image
  actually installs from — v0.5.2 only regenerated the workspace-root lock,
  so its intended change never shipped) back to the **exact v0.5.0 version
  set** — the configuration with months of proven production service. The
  v0.5.1 bulk regen bumped 73 packages unreviewed inside an unrelated feature
  PR; only uvicorn is a confirmed regression, but the remaining 72 are
  unvetted (tracing was down the whole time they've been live). Verified:
  zero version differences vs v0.5.0 except `freezegun` (see below); full
  test suite (110) passes on this set, including the #17 eventstream decode
  under botocore 1.34. Deliberate, reviewed dependency upgrades can follow
  separately with `tests/test_trace_propagation.py` as a gate.
- Revert the aws-xray-sdk floor to `>=2.14.0,<3`: the 2.14/2.15 theory from
  v0.5.2 was wrong — the image ran 2.14.0 in both the working and broken
  deployments.
- Declare `freezegun` in the package dev group: `tests/test_signing.py`
  imports it but it was only ever available transitively via the
  workspace-root lock (latent undeclared dependency).
- Build with `uv sync --locked` instead of `--frozen`, so a `uv.lock` that has
  drifted from `pyproject.toml` fails the image build instead of silently
  installing stale pins.

### Added
- `tests/test_trace_propagation.py`: boots a real uvicorn subprocess (matching
  the production CMD) and asserts an ALB-style `X-Amzn-Trace-Id` round-trips
  into the handler's current segment — fails on uvicorn >=0.47, passes on <0.47.

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