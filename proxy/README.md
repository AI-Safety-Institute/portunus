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

## Filter chain

1. **Common HTTP filters** — request-id, X-Ray tracing.
2. **`envoy.filters.http.local_ratelimit`** — first in the chain; rejects excess load before any backend RPC.
3. **`envoy.filters.http.ext_authz` #1** — gRPC call to `PortunusAuthServicer.Check` on headers only. Returns:
   - The real `Authorization` header (real api_key from the secret).
   - Request header `x-portunus-signing-required: true|false` (the composite-filter gate; not dynamic_metadata — that matcher input doesn't exist in Envoy 1.36).
   - `dynamic_metadata` carrying `principal_info` / `secret_arn` for the downstream ext_proc audit.
4. **`envoy.filters.http.composite`** — matches the `x-portunus-signing-required: true` request header via `HttpRequestHeaderMatchInput` and dispatches a second `ext_authz` (with `with_request_body: max_request_bytes=32MiB, allow_partial_message=false`). The inner filter reads the buffered body, computes Content-Digest, signs via KMS, and adds the Signature / Signature-Input headers. Unsigned tenants skip this entirely.
5. **`envoy.filters.http.ext_proc`** — gRPC call to `PortunusProcessServicer.Process` under `observability_mode: true` with `request_body_mode / response_body_mode: STREAMED`. Envoy ignores every `ProcessingResponse`, so the call is fire-and-forget from the customer's data path. Streams request / response bodies and post-101 WebSocket frames to Portunus for Firehose publication.
6. **`envoy.filters.http.router`** — forward to the target cluster.

## Routes

The listener exposes:

- `/ping` — direct 200 OK; both ext_authz and ext_proc are disabled per-route.
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
PORTUNUS_HOST=portunus.internal
PORTUNUS_GRPC_PORT=9000
PORTUNUS_API_KEY=pre-shared-key   # carried in initial_metadata as
                                   # `x-portunus-proxy-key`. Must equal
                                   # `GRPC_PROXY_API_KEY` on the Portunus
                                   # side; in CDK both come from the same
                                   # Secrets Manager value.

# Optional request signing (Anthropic)
ANTHROPIC_REQUEST_SIGNING_PROVIDER_KEY_ID=provider-key-id
ANTHROPIC_REQUEST_SIGNING_KMS_KEY_ARN=arn:aws:kms:...

# Rate limiting
RATE_LIMIT_PERCENT_ENABLED=0       # 0 disables
RATE_LIMIT_REQUESTS_PER_INTERVAL=100
RATE_LIMIT_INTERVAL_SECONDS=60
```

See `entrypoint.sh` for the full list of variables and defaults.

## Building

```bash
docker build -t api-key-proxy .
```
