# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- Audit pipeline migrated from Kinesis Data Streams to Firehose direct-PUT.
  Portunus now publishes audit records straight to per-record-type Firehose
  delivery streams; Firehose still lands on S3 in the same Parquet shape,
  so **the akp Glue ETL is unchanged**.
  - Env vars renamed `KINESIS_*_STREAM` -> `FIREHOSE_*_STREAM` (seven
    streams: metadata, request/response headers/body/trailers). Also
    `KINESIS_MAX_RECORD_SIZE` -> `FIREHOSE_MAX_RECORD_SIZE`,
    `KinesisConfig` -> `FirehoseConfig` in `portunus.config`. The akp
    companion PR provisions the new delivery streams and grants the task
    `firehose:PutRecord` IAM.
  - `StateService.get_kinesis_client` -> `get_firehose_client` (same
    lazy aiobotocore singleton pattern); the unused
    `get_kinesis_firehose_client` stub is gone.
  - `PublishService.publish_to_kinesis_data_stream` ->
    `publish_to_firehose`. Single fire-and-forget `PutRecord` per audit
    event. Firehose direct-PUT handles retry + DLQ server-side and
    removes the per-shard 1 MiB/s / 1000 records/s ceiling that
    motivated client-side workarounds.
  - LocalStack init renamed `localstack-init-kinesis.sh` ->
    `localstack-init-firehose.sh` and reprovisions Firehose with
    `DeliveryStreamType=DirectPut` (no upstream Kinesis source).
    `docker-compose.yaml` drops the `kinesis` service from
    LocalStack's `SERVICES` list.
  - **Quota dependency**: Firehose direct-PUT defaults are 5,000
    records/s and 5 MiB/s per account, 1,000 records/s or 1 MiB/s per
    delivery stream. The quota increase is filed by the akp companion
    PR; portunus must not assume it's in place at deploy time.

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