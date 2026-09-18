# Changelog

All notable changes to Portunus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Removed
- RFC 9421 request signing (the `signing_key` field on JSON secrets, the
  `Content-Digest`, `Signature` and `Signature-Input` upstream headers, and the
  `signable_request` / `signature*` fields on `/authorise`). Anthropic has
  deprecated the check and confirmed it can be turned off. Secrets that still
  carry a `signing_key` field keep working; the field is ignored. The `portunus`
  CLI's default session policy no longer grants `kms:Sign`, and LocalStack no
  longer starts KMS.

### Added
- Secrets may describe a token to mint instead of holding a key. The
  `anthropic_wif` type names a federation role, which Portunus assumes with
  the caller's credentials to obtain an STS web identity token and exchange
  it at the provider's `/v1/oauth/token` endpoint for a short-lived bearer
  token, returned with `output_header: authorization`. Federation role ARNs
  must be `arn:aws:iam::<account>:role<prefix><namespace>/<name>` with
  `<account>` in `FEDERATION_ALLOWED_ACCOUNT_IDS` (new env var; unset disables
  minting), `<prefix>` `FEDERATION_ROLE_PATH_PREFIX` (default `/portunus-fed/`)
  and `<namespace>` exactly two path segments, e.g.
  `arn:aws:iam::123456789012:role/portunus-fed/projects/example/example-grant@projects.example`.
  The identity token carries four request tags: the user (the caller's STS
  source identity, else its IAM role name), the caller's IAM role name, its
  role session name and its project, under `FEDERATION_USER_TAG_KEY`,
  `FEDERATION_PRINCIPAL_TAG_KEY`, `FEDERATION_SESSION_TAG_KEY` and
  `FEDERATION_PROJECT_TAG_KEY` (defaults `portunus:user`,
  `portunus:principal`, `portunus:session`, `portunus:project`).
  `FEDERATION_STS_ENDPOINT_URL` is also new. Mint secrets reject unknown
  fields. Minted results are cached until the earliest of `CACHE_DURATION`, the
  caller's credential expiry and one minute before the token expires;
  concurrent misses for one payload share a mint per process.
- `/authorise` returns 503 (`UpstreamServiceError`) when STS or the
  provider's token endpoint cannot be reached or answers 5xx/429, or when
  minting exceeds its 6 s deadline.
- The CLI's default session policy allows `sts:AssumeRole` on the federation
  roles in the secret's namespace, taken from the first two path segments of
  the secret's name: a secret named `projects/example/<name>` gets
  `arn:aws:iam::<caller account>:role/portunus-fed/projects/example/*`
  (`--federation-role-path` overrides the path). A secret with fewer than two
  leading path segments gets no `sts:AssumeRole` statement; a namespace segment
  containing `*` or `?` is rejected rather than widening the grant.
- `/authorise` responses may carry `output_header` and `output_prefix`, letting
  the backend choose which upstream header receives the credential and with
  what prefix. When absent, the proxy keeps using `API_KEY_HEADER` /
  `API_KEY_PREFIX`. The WebSocket relay honours the same fields (default
  `Authorization: Bearer`). Cached authorization results carry both fields.
  (#136)

### Changed
- JSON secrets that carry a `type` are validated strictly against that type
  and rejected on failure. JSON without a `type` keeps the previous
  behaviour (stored key, or used verbatim when it matches no schema).
- The proxy removes the header the auth payload arrived in (`API_KEY_HEADER`)
  from the upstream request and sets the header the credential is written to
  (`output_header`, else `API_KEY_HEADER`); when both name the same header this
  is the existing overwrite. The inbound header carries the caller's AWS
  credentials, so it is removed explicitly now that the credential can be
  written to a different header. Every other header, including other
  credential-shaped ones, is forwarded untouched so clients can carry
  provider-specific headers through. Header logging excludes
  `KNOWN_AUTH_HEADERS` (new proxy env var, default
  `authorization,x-api-key,x-goog-api-key,api-key`) plus the inbound and
  output headers, whether or not they were forwarded; previously only
  `API_KEY_HEADER` was excluded. The WebSocket relay applies the same
  forwarding and logging rules. (#136)

### Fixed
- A JSON secret that failed schema validation was logged with the pydantic
  error, which embeds the secret's contents. Only field paths and error
  types are logged now.
- The WebSocket relay forwarded the proxy's shared-secret header
  (`PORTUNUS_API_KEY_HEADER`, default `x-api-key`), which Envoy adds to every
  upgrade request it routes to Portunus, to the upstream and included it in the
  logged upgrade headers. With the default header name it is now stripped from
  both. (#136)

## [0.10.0] - 2026-09-16

### Fixed
- The backend keeps one Kinesis client per process instead of constructing a
  new aiobotocore client for every published record. Client construction
  (a fresh SSL context plus CA-bundle parse, ~30-40 ms of CPU) was about 80%
  of the backend's CPU per request under load, which capped the OpenAI proxy
  at roughly 500 requests/s with the backend fleet at its maximum task count.
  A single worker now handles about 7x the request rate.
- A cache read that times out during authentication now rejects the request
  (503 on HTTP, close code 1013 on WebSocket) instead of falling back to the
  full STS + Secrets Manager path. Under overload the timeout is a symptom of
  a starved event loop, and the fallback added ~1 s of work per request that
  Envoy had already abandoned. Other cache errors still fall back as before.

## [0.9.0] - 2026-09-11

### Added
- The proxy accepts `TARGET_MAX_REQUESTS` and `TARGET_MAX_PENDING_REQUESTS` to
  configure the target API's active and pending HTTP request circuit breakers.
  Both default to 1,024, preserving existing behaviour. Remaining breaker capacity
  is available through the private admin stats endpoint, and access logs include
  `response_code_details` for local failure diagnosis.

### Changed
- Routine Docker, Python, and GitHub Actions dependency updates.
  (#111, #118, #121, #127, #128)

## [0.8.0] - 2026-08-11

### Added
- The backend image now honours a `UVICORN_WORKERS` env var (default 1 —
  unchanged behaviour) so deployments can size the worker pool to the host,
  typically one worker per vCPU. A single worker can only use one core,
  which leaves multi-vCPU hosts underutilised and can back up the event
  loop under load. Note that per-process limits (`relay.max_connections`,
  the WS log queue worker pool) apply per worker, so per-container totals
  scale with the worker count. (#116)

## [0.7.0]

### Fixed
- `/cache/flush` now reliably invalidates fleet-wide: removed the in-process
  `@cached` layer on auth results, which was per-replica — a flush only cleared
  the replica that received it, leaving the rest serving stale (potentially
  compromised) keys for up to 500s — and could serve entries past the Redis
  TTL, which is deliberately capped at credential expiration. Redis is now the
  single source of cache truth; the aiocache dependency is dropped. (#95)

### Changed
- Removed unused pandas, pandas-stubs and pyarrow dev dependencies. (#97)
- Routine dependency updates via Dependabot: pyjwt, aiohttp, urllib3,
  boto3-stubs and the Python dev group; Envoy in the Lua test image; ruff-action
  and setup-uv in CI. (#56, #62, #64, #70, #72, #74, #80, #84, #93, #96)

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

[Unreleased]: https://github.com/AI-Safety-Institute/portunus/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.5.5...v0.6.0
[0.5.5]: https://github.com/AI-Safety-Institute/portunus/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/AI-Safety-Institute/portunus/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/AI-Safety-Institute/portunus/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/AI-Safety-Institute/portunus/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/AI-Safety-Institute/portunus/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/AI-Safety-Institute/portunus/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/AI-Safety-Institute/portunus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AI-Safety-Institute/portunus/releases/tag/v0.1.0
