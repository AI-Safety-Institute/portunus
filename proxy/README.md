# Proxy

Envoy-based reverse proxy that handles client traffic and delegates authentication and audit to Portunus via gRPC.

## Structure

```
proxy/
├── envoy.yaml      # Envoy configuration: listener, filter chain, ext_authz/ext_proc clusters, routes
├── entrypoint.sh   # Startup script — sets defaults and runs envsubst over envoy.yaml
├── Dockerfile      # Proxy container image
└── xray.json       # AWS X-Ray tracing config
```

There is no Lua filter and no proxy-utils library: all auth and audit logic lives in the Portunus gRPC servicers.

### Audit overload isolation

For separate authentication and audit admission, set `GRPC_AUDIT_PORT` on
Portunus to a different port from `GRPC_PORT`, and set
`PORTUNUS_AUDIT_GRPC_PORT` on Envoy to that same audit port. Portunus creates
two server instances; both retain the configured bind address and proxy-key
check. Authentication, signing, and health stay on the original port.
Leaving these settings unset preserves the shared-server configuration.

Set `GRPC_AUDIT_DROP_ON_PRESSURE=true` on Portunus to reject audit submissions
immediately when the bounded queue is full. Body limits and reserved metadata
space still apply, but once the queue fills, metadata and loss markers can
also be lost. Original losses and rejected loss markers have separate counters.
This favours forwarding availability during an audit outage; it does not make
audit delivery durable. Authentication and signing still fail closed. The two
servers share Python CPU, so this isolates admission rather than all resources.

## Filter chain

1. **Common HTTP filters** — request-id, X-Ray tracing.
2. **`envoy.filters.http.local_ratelimit`** — first in the chain; rejects excess load before any backend RPC.
3. **`envoy.filters.http.ext_authz` #1** — gRPC call to `PortunusAuthServicer.Check` on headers only. Returns:
   - The real `Authorization` header (real api_key from the secret).
   - Request header `x-portunus-signing-required: true|false` (the composite-filter gate; not dynamic_metadata — no `HttpRequestMetadataMatchInput` exists in the pinned Envoy 1.38.x).
   - `dynamic_metadata` carrying `principal_info` / `secret_arn` for the downstream ext_proc audit.
4. **`envoy.filters.http.composite`** — matches the `x-portunus-signing-required: true` request header via `HttpRequestHeaderMatchInput` and dispatches a second `ext_authz` (with `with_request_body: max_request_bytes=32MiB, allow_partial_message=false`). The inner filter reads the buffered body, computes Content-Digest, signs via KMS, and adds the Signature / Signature-Input headers. Unsigned tenants skip this entirely.
5. **`envoy.filters.http.ext_proc`** — gRPC call to `PortunusProcessServicer.Process` under `observability_mode: true` with `request_body_mode / response_body_mode: STREAMED`. Envoy ignores every `ProcessingResponse`, so the call is fire-and-forget from the customer's data path. Streams request / response bodies and post-101 WebSocket frames to Portunus for Firehose publication.
6. **`envoy.filters.http.router`** — forward to the target cluster.

## Routes

The listener exposes:

- `/ping` — direct 200 OK; reports Envoy liveness.
- `/healthz` — readiness backed by the backend gRPC readiness service. Configure load balancers to probe this endpoint.
- **WebSocket** — a route matched by `Upgrade: websocket` header. Goes to the `${WS_TARGET_HOST}` cluster with an `ExtProcPerRoute` override that flags the stream as WS (so the Process service parses frames via wsproto).
- **Default** — everything else goes to the `${TARGET_HOST}` upstream.

## Configuration

Injected via environment variables using `envsubst` in `entrypoint.sh`:

```bash
# Core
API_KEY_HEADER=authorization
API_KEY_PREFIX="Bearer "
PORTUNUS_HEADER_PREFIX=portunus
TARGET_HOST=api.example.com
WS_TARGET_HOST=ws.example.com     # optional, separate WS upstream

# Portunus gRPC
PORTUNUS_HOST=127.0.0.1
PORTUNUS_GRPC_PORT=9000
PORTUNUS_API_KEY=replace-with-random-shared-key
PORTUNUS_API_KEY_OPTIONAL=false

# Upstream concurrency (applies independently to HTTP and WebSocket clusters)
ENVOY_CONCURRENCY=1
TARGET_MAX_CONNECTIONS=10000
TARGET_MAX_REQUESTS=1024
TARGET_MAX_PENDING_REQUESTS=1024

# Rate limiting
RATE_LIMIT_PERCENT_ENABLED=0       # 0 disables
RATE_LIMIT_REQUESTS_PER_INTERVAL=100
RATE_LIMIT_INTERVAL_SECONDS=60
```

See `entrypoint.sh` for full list of environment variables and defaults.

`PORTUNUS_API_KEY` must match the backend's `GRPC_PROXY_API_KEY` and contain at
least 16 bytes. The proxy refuses to start with a missing or shorter key.
Local development can explicitly allow an empty key with
`PORTUNUS_API_KEY_OPTIONAL=true`, paired with the backend's corresponding
`GRPC_PROXY_API_KEY_OPTIONAL=true`; this does not permit a short nonempty key.

`ENVOY_CONCURRENCY` sets the number of Envoy worker threads. It defaults to one
instead of inheriting the host CPU count. Set a positive integer without leading
zeroes to match the CPU allocated to Envoy; larger values need workload validation.

Request concurrency is independent of connection concurrency, particularly for
HTTP/2. Both upstream clusters expose remaining request and pending-request
capacity through the loopback admin stats endpoint. Raising these limits
requires sufficient upstream, backend and memory capacity.

On shutdown, admin requests and active-stream draining share `DRAIN_TIME_S`.
If the admin endpoint cannot respond within that deadline, the entrypoint
terminates Envoy; sessions still open at the deadline can be disconnected.

Request signing is **not** proxy-side configuration: there is no signing env
var. A tenant is a signing tenant iff its Secrets Manager secret carries a
`signing_key` block (`{"provider_id": ..., "kms_key_arn": ...}`), which
`Check` returns alongside the api_key. The proxy only reacts to the
`x-portunus-signing-required` header that decision sets, so enabling signing
for a tenant needs no proxy redeploy.

### Terminating TLS at the proxy

By default the proxy listener is plain HTTP and TLS is expected to terminate in
front of it (e.g. a load balancer). To terminate TLS at the proxy itself,
provide `/envoy/cert.crt` and `/envoy/cert.key` (see the `DOWNSTREAM_TLS_TRANSPORT_SOCKET`
block in `entrypoint.sh`).

The container runs as the non-root `envoy` user (uid 101), so those cert files
**must be readable by uid 101**. When mounting them at runtime, set the source
permissions/ownership accordingly — e.g. Kubernetes `securityContext.fsGroup: 101`,
or `--chown` on a bind mount. If the key is unreadable, Envoy fails to start with
a cert-load error.

## Access-log timings

The JSON access log on stdout includes the following fields. Timings are elapsed
wall-clock milliseconds:

| Field | Meaning |
| --- | --- |
| `duration` | Request start to completion, including response transfer. |
| `upstream_pool_wait_ms` | Time waiting for the upstream connection pool, including connection establishment when needed. |
| `request_sent_ms` | Request start to the last request byte sent upstream. |
| `first_response_ms` | Request start to the first upstream response byte. |
| `upstream_attempts` | Number of upstream attempts, including retries (a count, not a duration). |
| `openai_processing_ms` | The upstream's optional `openai-processing-ms` response header, recorded as supplied. |

For completed requests with one upstream attempt, subtract `request_sent_ms`
from `first_response_ms` to measure the wait after sending the request. This
includes network and upstream processing time; it is not proxy CPU time.
Analyse retried requests separately: the upstream timing fields can refer to
different attempts. Streaming response transfer is included in `duration`, not
`first_response_ms`; these fields do not measure individual tokens or WS messages.

Envoy emits its timings and attempt count as JSON numbers; the provider header
is a string. Missing timings or headers are `null`, including on requests that
never reach the upstream or end before the relevant event. Treat unavailable or
nonnumeric timing values as missing, not zero. The provider header is supporting
evidence, not an independently measured duration. Access-log timings do not
depend on X-Ray sampling or audit delivery.

## Building

```bash
cd proxy
docker build -t portunus-proxy .
```

### X-Ray sampling

`XRAY_SAMPLING_RATE` sets the default X-Ray request sampling probability from
`0` to `1` (default `1.0`). For example, `0.01` samples approximately 1% of
otherwise eligible requests. The fixed reservoir remains zero, and existing
health-check exclusions are preserved. Invalid values prevent startup.

Incoming trace IDs and sampling decisions are retained. Consequently a caller's
`Sampled=1` can override this default: it is not a hard export-rate limit or a
way to disable tracing completely. Python follows Envoy's sampling decision
through authenticated gRPC metadata. Each selected request can emit several
segments, so size the export budget using segment volume as well as request rate.
