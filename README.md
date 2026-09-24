# Portunus

![Portunus](portunus.png)

**Portunus** is a secure API key proxy. Clients authenticate with temporary AWS credentials and Portunus transparently swaps them for the real API key stored in AWS Secrets Manager before forwarding requests to upstream targets. Traffic is submitted to Firehose for best-effort auditing; monitor publication and capture-loss metrics.

It runs as two cooperating components:

- **Envoy proxy** (one deployment per target host). Envoy terminates the client's connection and applies a filter chain:
  - **`ext_authz`** calls Portunus's `Check` gRPC servicer to authenticate the request and (for signing tenants) compute the RFC 9421 signature headers.
  - **`ext_proc`** streams request and response bodies — and post-101 WebSocket frames — to Portunus's `Process` gRPC servicer for audit publication.
- **Portunus backend**. A pure gRPC process (`python -m portunus.grpc.server` — the FastAPI/REST surface is retired by the unreleased gRPC cutover; 0.6.0 and 0.7.0 still shipped it) hosting the two servicers above plus the standard `grpc.health.v1.Health` and reflection services. Envoy answers `/ping` (Envoy process liveness) and `/healthz` (gated on Portunus's `"readiness"` gRPC health service — the ALB health-check target); flushing the shared auth cache is an operator runbook — see [`docs/runbooks/flush-auth-cache.md`](docs/runbooks/flush-auth-cache.md) — not an HTTP endpoint:
  - Decodes the base64-encoded payload in the client's `Authorization` header — `{credentials, secret_arn}` — and uses those AWS credentials to fetch the real API key from Secrets Manager. Deployments must configure network access and IAM permissions for their intended trust boundary.
  - Secrets can be stored as plaintext (`"sk-…"`) or as JSON with a target-host check (`{"secret":"sk-…","host":"api.openai.com"}`); the latter only authorises for matching upstreams.
  - Returns the real key as a header mutation; Envoy applies it before forwarding upstream.
  - Streams metadata, headers, and bodies to per-stream Kinesis data streams; a Firehose per stream archives them in S3.

Supporting AWS services:

- **Kinesis Data Streams → Firehose** for the audit pipeline. Portunus packs audit records (newline-delimited, up to 256 KiB / 500 per KDS record) under random partition keys; Firehose deaggregates them before partitioning and delivery.
- **AWS Secrets Manager** for the real API keys.
- **AWS KMS** for request signing (signing tenants only).
- **CloudWatch Logs** for the structured logs and the embedded (EMF) metrics
  Portunus writes to stdout.

## Data flow

```mermaid
sequenceDiagram
    participant Client
    participant Envoy as Envoy proxy
    participant Auth as portunus<br/>ext_authz Check
    participant Proc as portunus<br/>ext_proc Process
    participant Redis
    participant AWS as Secrets Manager / KMS / STS
    participant Target as Upstream target
    participant KDS as Kinesis Data Streams

    Client->>Envoy: Initial request
    Envoy->>Auth: Check (headers only)
    Auth->>Redis: Cached auth result?
    Auth-->>AWS: (miss) STS get-caller-identity
    Auth-->>AWS: (miss) Secrets Manager get-secret-value
    Auth-->>Redis: (miss) Cache result
    Auth-->>Envoy: Header mutations (real api_key, signing flag)<br/>+ dynamic_metadata (principal_info, secret_arn)

    Note over Envoy: If signing required:<br/>composite filter dispatches<br/>a second ext_authz pass<br/>that buffers the body, signs<br/>via KMS, and returns<br/>Content-Digest + Signature headers.

    Envoy->>Target: Forward request
    Envoy-->>Proc: Stream request headers (carry dynamic_metadata) + body chunks
    Proc->>KDS: Publish principal metadata record (off the auth-latency path)
    Target-->>Envoy: Stream response
    Envoy-->>Client: Stream response to client
    Envoy-->>Proc: Stream response headers + body chunks
    Proc->>KDS: Publish records per chunk (packed)
```

## Configuration

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `AWS_REGION` | AWS region for all service clients | *(required)* |
| `API_KEY_HEADER` | Header name carrying the encoded payload | `authorization` |
| `API_KEY_PREFIX` | Prefix on the header value | `Bearer ` |
| `PORTUNUS_HEADER_PREFIX` | Prefix for proxy response headers (`x-{prefix}-*`) | `portunus` |
| `GRPC_ENABLED` | Required to be `true` for this gRPC-only image | `false` |
| `GRPC_HOST` | Interface the gRPC server binds to. Loopback by default for the sidecar topology where Envoy reaches Portunus on localhost. Set to `0.0.0.0` if Envoy and Portunus run in separate network namespaces. | `127.0.0.1` |
| `GRPC_PORT` | gRPC server listen port | `9000` |
| `GRPC_PROXY_API_KEY` | Key of at least 16 bytes matching proxy `PORTUNUS_API_KEY` | - |
| `GRPC_PROXY_API_KEY_OPTIONAL` | When `true`, allow an empty `GRPC_PROXY_API_KEY` (dev only) | `false` |
| `CACHE_DURATION` | Authorisation cache TTL (seconds) | - |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` | Redis connection settings | `localhost` / `6379` / - |
| `REDIS_MAX_CONNECTIONS` | Max Redis connections | `200` |
| `FIREHOSE_METADATA_STREAM` | Firehose delivery stream for principal metadata records | *(required)* |
| `FIREHOSE_REQUEST_HEADERS_STREAM` / `FIREHOSE_REQUEST_BODY_STREAM` / `FIREHOSE_REQUEST_TRAILERS_STREAM` | Request-side delivery streams | *(all required)* |
| `FIREHOSE_RESPONSE_HEADERS_STREAM` / `FIREHOSE_RESPONSE_BODY_STREAM` / `FIREHOSE_RESPONSE_TRAILERS_STREAM` | Response-side delivery streams | *(all required)* |
| `FIREHOSE_WS_SUMMARY_STREAM` | Per-connection WebSocket summary records (`WSSummaryRecord`) | - |
| `RATE_LIMIT_PERCENT_ENABLED` / `RATE_LIMIT_INTERVAL_SECONDS` / `RATE_LIMIT_REQUESTS_PER_INTERVAL` | Optional rate limiting | `0` / - / - |
| `REDIS_USE_TLS` | TLS to Redis | `true` |

## Local development

### Setup

```bash
uv sync
```

### Running locally

```bash
docker compose up --build
```

By default the proxy points at an included [httpbun](https://httpbun.com/) instance. Send a request through the stack:

```bash
TOKEN=$(python - <<'PY'
import base64
import json

payload = {
    "credentials": {
        "access_key_id": "000000000000",
        "secret_access_key": "test",
        "session_token": "test",
    },
    "secret_arn": "arn:aws:secretsmanager:eu-west-2:000000000000:secret:test-api-key",
}
print(base64.b64encode(json.dumps(payload).encode()).decode())
PY
)
curl http://localhost:8888/headers -H "Authorization: Bearer $TOKEN"
```

### Constructing a payload

```python
from portunus.services.payload_service import encode_payload

# credentials dict from STS assume-role or get-session-token
payload = encode_payload(
    credentials, "arn:aws:secretsmanager:eu-west-2:123456789012:secret:my-api-key"
)
```

## Running tests

The test suite splits into two surfaces. The first runs in CI on every push and PR; the second needs Docker (and is slow) and runs in the same job after the unit tests pass.

### Unit tests (fast, in-CI)

```bash
cd portunus && uv run pytest -q
```

Covers the gRPC servicers (auth + proc) in isolation with `Fake*` collaborators, plus secrets / cache / signing / publish-queue logic and the schema-consistency check for the Glue ETL.

### Behaviour and end-to-end tests (slow, docker-compose required)

Bring the stack up once and run the broader suite from the repo root:

```bash
docker compose up --build --wait
uv run --group dev pytest tests/ -q
```

The same fixtures cover:

- `tests/test_http_proxy_behaviour.py` — parameterised HTTP corpus driven through Envoy → Portunus → httpbun. Auth, methods, headers, security adversarial cases.
- `tests/test_ws_proxy_behaviour.py` — WebSocket upgrade, frame round-trip, close-code propagation, abrupt-disconnect handling.
- `tests/test_e2e.py` — non-corpus HTTP behaviours (custom header prefix, error-response diagnostics).
- `tests/test_e2e_signing.py` — request-signing against the Anthropic test vectors via LocalStack KMS.
- `tests/test_inspect_compat.py` — OpenAI SDK driven through Portunus via Inspect AI.
- `tests/test_redis_cache.py` — Redis cache TTL and signing-key handling.

Tests that need the Docker stack are tagged `@pytest.mark.slow`. CI runs both surfaces in `.github/workflows/test.yml`; the lint and type-check workflows skip the Docker-driven lane.

### CloudWatch integration

Portunus does not export traces. Per-request correlation rides on Envoy's
`x-request-id` (and the inbound `x-amzn-trace-id`, when present), which appears
on every structured log line and every Firehose audit record; aggregate
behaviour comes from [CloudWatch embedded metrics
(EMF)](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format.html)
that Portunus aggregates in-process and flushes to stdout once per
`METRICS_FLUSH_INTERVAL_SECONDS`. CloudWatch Logs extracts them with no agent
and no metric filter. Set `METRICS_ENABLED=true` to turn them on (off by
default, including in `docker-compose.yaml`, so local stdout stays readable).

For [CloudWatch](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html) integration to work locally, uncomment the logging settings for the relevant services and provide credentials in `~/.aws/credentials` (default profile). See `docker-compose.yaml`.

## Known issues

- **Audit record size**: Kinesis and Firehose have a 1 MiB max record size. Large payloads are chunked automatically (one record per chunk), but Envoy and Portunus both hold payloads in memory which can cause memory pressure under heavy load with large bodies.
- **Scaling lag**: Deployments must configure capacity and scaling. Rapid load increases can exhaust request or signing capacity before additional instances become ready.
- **WebSocket signing not supported**: If a tenant configured with a `signing_key` initiates a WebSocket upgrade, the proxy rejects the upgrade with `HTTP 400` and a body explaining the limitation. Either remove the `signing_key` from the tenant secret to use WebSocket, or use HTTPS for signed requests. The explicit rejection prevents an unsupported upgrade from being signed as an empty HTTP body.

## Streaming

The proxy handles streaming responses (e.g. SSE from LLM APIs) efficiently:

- Request bodies are buffered (up to 32 MiB) only when the tenant requires request signing; unsigned tenants stream end-to-end with no buffering. Larger signed bodies receive HTTP 413 from Envoy rather than being silently truncated.
- Responses stream directly to the client as they arrive. Each response chunk is logged to Firehose individually with a monotonic `chunk_id`; downstream consumers must reassemble by `request_id` and validate completion/loss markers.
- Envoy's `stream_idle_timeout` is set to 3600s for long-running streams.
