# Proxy

Envoy-based reverse proxy that handles client traffic and delegates authentication and audit to Portunus via gRPC.

## Structure

```
proxy/
├── envoy.yaml      # Envoy configuration: listener, filter chain, ext_authz/ext_proc clusters, routes
├── entrypoint.sh   # Startup script — sets defaults, runs envsubst over envoy.yaml, drains on SIGTERM
└── Dockerfile      # Proxy container image
```

There is no Lua filter and no proxy-utils library: all auth and audit logic lives in the Portunus gRPC servicers.

## Filter chain

1. **`envoy.filters.http.health_check`** — answers `/healthz` (see Routes) before anything else, so probes are never rate-limited or authenticated.
2. **`envoy.filters.http.local_ratelimit`** — rejects excess load before any backend RPC.
3. **`envoy.filters.http.ext_authz`** — gRPC call to `PortunusAuthServicer.Check` on headers only; the request body is never sent, so requests stream end to end. `failure_mode_allow: false` and a 10 s timeout (Portunus answers within 9 s). On success it returns:
   - The upstream credential header (the secret's `output_header`, else the backend's `API_KEY_HEADER`) set to the real key, and removal of the inbound `API_KEY_HEADER` when that is a different header.
   - `dynamic_metadata` carrying `upstream_auth_header`, `principal_info` and `secret_arn` for the downstream ext_proc audit.
4. **`envoy.filters.http.ext_proc`** — gRPC call to `PortunusProcessServicer.Process` under `observability_mode: true` with `request_body_mode / response_body_mode: STREAMED` and `failure_mode_allow: true`. Envoy ignores every `ProcessingResponse`, so the call is fire-and-forget from the customer's data path. Streams request / response headers, bodies, trailers and post-101 WebSocket frames to Portunus, which publishes them to Kinesis Data Streams. It uses its own cluster (`portunus_extproc_cluster`) so audit pressure cannot exhaust the ext_authz circuit breakers.
5. **`envoy.filters.http.router`** — forward to the target cluster.

Envoy generates `x-request-id` for every request and replaces any client-supplied value: `use_remote_address: true` makes every request an edge request, with `XFF_NUM_TRUSTED_HOPS` trusted proxies in front (default 1, the load balancer; 0 when clients reach Envoy directly), and Envoy appends the peer address to `x-forwarded-for` and strips client-sent `x-envoy-*` headers. The route_config strips inbound `x-portunus-debug-id`, `x-portunus-proxy-key` and `x-portunus-target-host`; the proxy key and target host reach Portunus only as gRPC initial metadata.

## Routes

The listener exposes:

- `/ping` — direct 200 with `x-{PORTUNUS_HEADER_PREFIX}-ping: true`; ext_authz and ext_proc are disabled. Reports Envoy liveness only.
- `/healthz` — 200 while Portunus's standard gRPC health service (the default service, `""`) is `SERVING` (Envoy actively checks it through `portunus_health_cluster`), 503 otherwise or while draining. ext_authz and ext_proc are disabled on this route too, so probes produce no audit records. When `PORTUNUS_AUDIT_GRPC_PORT` differs from `PORTUNUS_GRPC_PORT`, the entrypoint adds `portunus_audit_health_cluster` on the audit port and `/healthz` requires both. Configure load balancers to probe this endpoint.
- **WebSocket** — matched by an `Upgrade: websocket` header (case-insensitive). Goes to the `ws_upstream` cluster (`WS_TARGET_HOST`), passes `WS_TARGET_HOST` to `Check` as the target host, and marks the stream as WebSocket for ext_proc so the Process service parses frames with wsproto. Streams last at most `WS_MAX_CONNECTION_LIFETIME` seconds (`max_stream_duration`, default 3300: the limit the Python relay used to enforce).
- **Default** — everything else goes to the `${TARGET_HOST}` upstream, retrying up to 3 times on connection reset.

### Audit overload isolation

For separate authentication and audit admission, set `GRPC_AUDIT_PORT` on
Portunus to a different port from `GRPC_PORT`, and set
`PORTUNUS_AUDIT_GRPC_PORT` on Envoy to that same audit port. Portunus creates
two server instances; both retain the configured bind address and proxy-key
check. Authentication stays on the original port; both ports serve the health
service, and `/healthz` requires both.
Leaving these settings unset preserves the shared-server configuration.

Set `GRPC_AUDIT_DROP_ON_PRESSURE=true` on Portunus to reject audit submissions
immediately when the bounded queue is full. Body limits and reserved metadata
space still apply, but once the queue fills, metadata records can also be
lost. A dropped body chunk shows as a gap in its body's `chunk_id` sequence and
in Portunus's `dropped_total` counter (the `DroppedRecords` metric).
This favours forwarding availability during an audit outage; it does not make
audit delivery durable. Authentication still fails closed. The two
servers share Python CPU, so this isolates admission rather than all resources.

To isolate CPU as well, run two Portunus processes (e.g. two containers in the
same task) from the same image: one with `GRPC_ROLE=auth` (ext_authz and
health on `GRPC_PORT`, no Kinesis config needed) and one with
`GRPC_ROLE=audit` (ext_proc and health on `GRPC_AUDIT_PORT`, falling back to
`GRPC_PORT`). Point Envoy's `PORTUNUS_AUDIT_GRPC_PORT` at the audit process.
Each container's image health check probes the port its role serves, and
`/healthz` fails when either process is down or draining.
The default `GRPC_ROLE=all` keeps both servicers in one process.

## Configuration

Injected via environment variables using `envsubst` in `entrypoint.sh`:

```bash
# Core
PORTUNUS_HEADER_PREFIX=portunus
TARGET_HOST=api.example.com
TARGET_PORT=443
WS_TARGET_HOST=ws.example.com     # optional, separate WS upstream (default TARGET_HOST)
WS_TARGET_PORT=443                # optional (default TARGET_PORT)
WS_MAX_CONNECTION_LIFETIME=3300   # WebSocket lifetime cap in seconds
XFF_NUM_TRUSTED_HOPS=1            # proxies in front of Envoy (1 = the ALB; 0 = direct)

# Portunus gRPC
PORTUNUS_HOST=127.0.0.1
PORTUNUS_GRPC_PORT=9000
PORTUNUS_AUDIT_GRPC_PORT=9000     # optional (default PORTUNUS_GRPC_PORT)
PORTUNUS_API_KEY=replace-with-random-shared-key
PORTUNUS_API_KEY_OPTIONAL=false

# Upstream concurrency (applies independently to HTTP and WebSocket clusters)
ENVOY_CONCURRENCY=1
TARGET_MAX_CONNECTIONS=10000
TARGET_MAX_REQUESTS=1024
TARGET_MAX_PENDING_REQUESTS=1024

# Shutdown
DRAIN_TIME_S=60

# Rate limiting
RATE_LIMIT_PERCENT_ENABLED=0       # 0 disables
RATE_LIMIT_REQUESTS_PER_INTERVAL=100
RATE_LIMIT_INTERVAL_SECONDS=60
```

See `entrypoint.sh` and `Dockerfile` for the full list of environment variables and defaults.

`API_KEY_HEADER` and `API_KEY_PREFIX` (which header carries the client's
payload, and the credential's default header and prefix) are backend settings
now; the proxy does not read them.

`PORTUNUS_API_KEY` must match the backend's `GRPC_PROXY_API_KEY` and contain at
least 16 bytes. The proxy refuses to start with a missing or shorter key.
Local development can explicitly allow an empty key with
`PORTUNUS_API_KEY_OPTIONAL=true`, paired with the backend's corresponding
`GRPC_PROXY_API_KEY_OPTIONAL=true`; this does not permit a short nonempty key.

`ENVOY_CONCURRENCY` sets the number of Envoy worker threads. It defaults to one
instead of inheriting the host CPU count. Set a positive integer without leading
zeroes to match the CPU allocated to Envoy; larger values need workload validation.

`XFF_NUM_TRUSTED_HOPS` is the number of trusted proxies between the client and
Envoy. It must match the deployment: 1 behind the ALB, 0 when clients connect
directly (docker-compose), one more for every extra hop such as a middleware
sidecar in front of Envoy. It sets where the client address is read from
`x-forwarded-for` and whether a downstream `x-forwarded-proto` is trusted; it
does not affect `x-request-id`, which Envoy always regenerates.

Request concurrency is independent of connection concurrency, particularly for
HTTP/2. Both upstream clusters expose remaining request and pending-request
capacity through the loopback admin stats endpoint. Raising these limits
requires sufficient upstream, backend and memory capacity.

On shutdown, admin requests and active-stream draining share `DRAIN_TIME_S`.
If the admin endpoint cannot respond within that deadline, the entrypoint
terminates Envoy; sessions still open at the deadline can be disconnected.

The entrypoint refuses to start Envoy other than 1.38.x (`EXPECTED_ENVOY_MINOR`):
older versions boot this config but can crash on shutdown with an audit stream
in flight.

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
evidence, not an independently measured duration. Access-log timings are
independent of audit delivery.

## Building

```bash
cd proxy
docker build -t portunus-proxy .
```

### Request correlation

The proxy exports no traces. Envoy generates `x-request-id` for every request
and the JSON access log records it, so a request is traceable across the access
log, Portunus's structured logs, and the audit records by that one id. Every
response carries it too (`always_set_request_id_in_response`), so a client can
quote the id of a request it wants looked up.
An inbound `x-amzn-trace-id` is forwarded untouched and its `Root=` id is
attached to Portunus's log lines for correlation with whatever upstream set it.

Aggregate behaviour (Check outcomes, auth latency, cache hit rates, audit queue
health, event-loop lag) comes from the CloudWatch EMF metrics Portunus flushes
to stdout — see `METRICS_*` in the Portunus README. There is no per-request
sampling knob because there is nothing per-request to sample.
