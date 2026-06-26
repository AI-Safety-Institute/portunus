# Portunus

![Portunus](portunus.png)

**Portunus** is a secure API key proxy. Clients authenticate with temporary AWS credentials and Portunus transparently swaps them for the real API key stored in AWS Secrets Manager before forwarding requests to upstream targets. All traffic is logged to Firehose for auditing.

It runs as two cooperating components:

- **Envoy proxy** (one deployment per target host). Envoy terminates the client's connection and applies a filter chain:
  - **`ext_authz`** calls Portunus's `Check` gRPC servicer to authenticate the request and (for signing tenants) compute the RFC 9421 signature headers.
  - **`ext_proc`** streams request and response bodies — and post-101 WebSocket frames — to Portunus's `Process` gRPC servicer for audit publication.
- **Portunus backend**. A FastAPI service that hosts the two gRPC servicers above plus the `/ping` operator endpoint (flushing the shared auth cache is now an operator runbook — see [`docs/runbooks/flush-auth-cache.md`](docs/runbooks/flush-auth-cache.md) — not an HTTP endpoint):
  - Decodes the base64-encoded payload in the client's `Authorization` header — `{credentials, secret_arn}` — and uses those AWS credentials to fetch the real API key from Secrets Manager. Clients can't reach Secrets Manager directly; network policy enforces this.
  - Secrets can be stored as plaintext (`"sk-…"`) or as JSON with a target-host check (`{"secret":"sk-…","host":"api.openai.com"}`); the latter only authorises for matching upstreams.
  - Returns the real key as a header mutation; Envoy applies it before forwarding upstream.
  - Streams metadata, headers, and bodies to per-stream Firehose delivery streams for archival in S3.

Supporting AWS services:

- **Kinesis Firehose (direct-PUT)** for the audit pipeline.
- **AWS Secrets Manager** for the real API keys.
- **AWS KMS** for request signing (signing tenants only).
- **AWS X-Ray** for distributed tracing.

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
    participant Firehose

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
    Proc->>Firehose: Publish principal metadata record (off the auth-latency path)
    Target-->>Envoy: Stream response
    Envoy-->>Client: Stream response to client
    Envoy-->>Proc: Stream response headers + body chunks
    Proc->>Firehose: Publish records per chunk
```

## Configuration

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `AWS_REGION` | AWS region for all service clients | *(required)* |
| `API_KEY_HEADER` | Header name carrying the encoded payload | `authorization` |
| `API_KEY_PREFIX` | Prefix on the header value | `Bearer ` |
| `PORTUNUS_HEADER_PREFIX` | Prefix for proxy response headers (`x-{prefix}-*`) | `portunus` |
| `GRPC_ENABLED` | Start the ext_authz / ext_proc gRPC server | `false` |
| `GRPC_HOST` | Interface the gRPC server binds to. Loopback by default for the sidecar topology where Envoy reaches Portunus on localhost. Set to `0.0.0.0` if Envoy and Portunus run in separate network namespaces. | `127.0.0.1` |
| `GRPC_PORT` | gRPC server listen port | `9000` |
| `GRPC_PROXY_API_KEY` | Pre-shared key Envoy presents in `x-portunus-proxy-key` initial metadata | - |
| `GRPC_PROXY_API_KEY_OPTIONAL` | When `true`, allow an empty `GRPC_PROXY_API_KEY` (dev only) | `false` |
| `CACHE_DURATION` | Authorisation cache TTL (seconds) | - |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` | Redis connection settings | `localhost` / `6379` / - |
| `REDIS_MAX_CONNECTIONS` | Max Redis connections | `200` |
| `FIREHOSE_METADATA_STREAM` | Firehose delivery stream for principal metadata records | - |
| `FIREHOSE_REQUEST_HEADERS_STREAM` / `FIREHOSE_REQUEST_BODY_STREAM` / `FIREHOSE_REQUEST_TRAILERS_STREAM` | Request-side delivery streams | - |
| `FIREHOSE_RESPONSE_HEADERS_STREAM` / `FIREHOSE_RESPONSE_BODY_STREAM` / `FIREHOSE_RESPONSE_TRAILERS_STREAM` | Response-side delivery streams | - |
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
curl -X GET http://localhost:8888/headers \
  -H "Authorization: Bearer eyJjcmVkZW50aWFscyI6eyJhY2Nlc3Nfa2V5X2lkIjoiQUtJQVRFU1QiLCJzZWNyZXRfYWNjZXNzX2tleSI6IlNFQ1JFVFRFU1QiLCJzZXNzaW9uX3Rva2VuIjoiVEVTVFRPS0VOIn0sInNlY3JldF9hcm4iOiJhcm46YXdzOnNlY3JldHNtYW5hZ2VyOnVzLWVhc3QtMToxMjM0NTY3ODkwMTI6c2VjcmV0OnRlc3Qtc2VjcmV0In0="
```

### Constructing a payload

```python
from portunus.services.payload_service import encode_payload

# credentials dict from STS assume-role or get-session-token
payload = encode_payload(credentials, "arn:aws:secretsmanager:eu-west-2:123456789012:secret:my-api-key")
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

### X-Ray and CloudWatch integration

For [X-Ray](https://docs.aws.amazon.com/xray/latest/devguide/aws-xray.html) integration to work locally you need valid AWS credentials in your environment when you start the docker stack. See `docker-compose.yaml`.

For [CloudWatch](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html) integration to work locally, uncomment the logging settings for the relevant services and provide credentials in `~/.aws/credentials` (default profile). See `docker-compose.yaml`.

## Known issues

- **Firehose record size**: Firehose has a 1 MiB max record size. Large payloads are chunked automatically (one record per chunk), but Envoy and Portunus both hold payloads in memory which can cause memory pressure under heavy load with large bodies.
- **Scaling lag**: The backend autoscales; some 504 / 503 responses are expected during rapid load increases and resolve as the service scales up.
- **WebSocket signing not supported**: If a tenant configured with a `signing_key` initiates a WebSocket upgrade, the proxy rejects the upgrade with `HTTP 400` and a body explaining the limitation. Either remove the `signing_key` from the tenant secret to use WebSocket, or use HTTPS for signed requests. No provider exposes signed WebSocket endpoints today, so this is unlikely to constrain real workloads; the explicit rejection ensures a clear customer-visible failure mode rather than silently signing an empty payload.

## Streaming

The proxy handles streaming responses (e.g. SSE from LLM APIs) efficiently:

- Request bodies are buffered (up to 32 MiB) only when the tenant requires request signing; unsigned tenants stream end-to-end with no buffering. Larger signed bodies receive HTTP 413 from Envoy rather than being silently truncated.
- Responses stream directly to the client as they arrive. Each response chunk is logged to Firehose individually with a monotonic `chunk_id`; the akp Glue ETL reassembles by `request_id` at aggregation time.
- Envoy's `stream_idle_timeout` is set to 3600s for long-running streams.
