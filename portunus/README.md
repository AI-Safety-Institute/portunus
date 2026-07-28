# Portunus (backend package)

The `portunus/` Python package is the gRPC servicer process that Envoy delegates auth and audit to. The root [README](../README.md) covers the overall system; this README is the dev-facing map of the package and how to run its unit tests.

For architecture and request flow (ext_authz `Check`, the composite-filter signing pass, ext_proc `Process`), see the [repo-root `CLAUDE.md`](../CLAUDE.md).

## Module map

```
portunus/
  cli.py            Console entry point (generates proxy auth payloads).
  config.py         Env-driven PortunusConfig (singleton at import time).
  exceptions.py     Service exception types (AuthenticationError, CredentialsError, ...).
  logging.py        StructuredLogFormatter: JSON log lines on stdout, enriched
                    with the request_id / trace_id contextvars set by
                    xray_service. Configured at import time.
  metrics.py        CloudWatch EMF reporter: emits Embedded Metric Format
                    JSON lines on a dedicated stdout logger (namespace
                    portunus-proxy), bypassing the structured formatter.
  models.py         Pydantic request models and dataclass Firehose record types
                    (MetadataRecord, RequestBodyRecord, ResponseBodyRecord,
                    WSSummaryRecord, JoinedLogRecord). Ships standalone into the
                    akp Glue ETL zip, so all portunus.* imports here are lazy.
  util.py           Small helpers (timestamps, wait_until).

  grpc/
    server.py            Builds and starts the grpc.aio server; registers both
                         servicers and the proxy-key interceptor.
    auth_servicer.py     PortunusAuthServicer.Check — Envoy ext_authz. Auth pass
                         decodes the payload, hits AuthService, forwards principal
                         metadata to ext_proc via dynamic_metadata. Signing pass
                         (composite filter, second Check with buffered body)
                         computes Content-Digest and RFC 9421 headers.
    proc_servicer.py     PortunusProcessServicer.Process — Envoy ext_proc. Streams
                         request/response body chunks and post-101 WebSocket
                         frames into a bounded publish queue.
    frame_observer.py    wsproto-driven WebSocket frame parser (PerMessageDeflate
                         finalize()'d against the upstream's Sec-WebSocket-Extensions).
    proxy_auth.py        Server interceptor validating x-portunus-proxy-key on
                         the initial metadata.

  services/
    auth_service.py            STS get-caller-identity + Secrets Manager fetch +
                               target-host validation, cached via CacheService.
    secrets_service.py         aiobotocore Secrets Manager client; boto_session
                               is constructor-injectable for tests.
    cache_service.py           Redis-backed auth-response cache. The key is the
                               sha256 of the independently-hashed target_host
                               and payload digests — no delimiter, so no
                               (host, payload) pair can collide by shifting
                               bytes across a separator.
    signing_service.py         RFC 9421 (HTTP Message Signatures) over AWS KMS.
                               KMS.Sign is sync boto3 offloaded via asyncio.to_thread.
    publish_service.py         Firehose publish helpers; one method per record type.
    publish_queue.py           Bounded async queue with headroom reserved for
                               metadata vs body submits.
    state_service.py           Redis client lifecycle.
    payload_service.py         Base64 / JSON payload encode/decode.
    arn_service.py             Secret ARN parsing.
    xray_service.py            X-Ray tracing helpers; owns the request_id /
                               trace_id contextvars.
```

## gRPC-service environment variables

These gate the servicer process specifically; the root README documents the rest.

| Variable | Purpose |
|---|---|
| `GRPC_ENABLED` | Must be `true` (default `false`). The gRPC server is the process's only surface, so when it is unset/false `run()` logs "nothing to serve" and returns immediately instead of starting anything. `docker-compose.yaml` and the akp task definition both set it. |
| `GRPC_PORT` | gRPC listen port (default `9000`). |
| `GRPC_PROXY_API_KEY` | Pre-shared key Envoy presents in `x-portunus-proxy-key` initial metadata; enforced by `grpc/proxy_auth.py`. |
| `GRPC_PROXY_API_KEY_OPTIONAL` | When `true`, an empty `GRPC_PROXY_API_KEY` is permitted (dev only). |

See `portunus/config.py` for the rest (Redis, Firehose stream names, rate limiting, TLS toggles, header naming).

## Tests

Unit tests live in `portunus/tests/` and run without Docker:

```bash
cd portunus && uv run pytest -q
```

Coverage includes both gRPC servicers in isolation (with `Fake*` collaborators rather than `MagicMock`, so assertions can read the data flowing through), the publish queue, the Redis cache, the RFC 9421 signing implementation, frame parsing, and a schema-consistency check that guards the Glue ETL contract.

Behaviour and end-to-end tests live at the repo root in `tests/` and require `docker compose up --build --wait`; see the [root README](../README.md#running-tests).

## Running the service locally

The intended entry point is the full stack (`docker compose up --build` at the repo root), which brings up Envoy, Redis, LocalStack, and an httpbun upstream alongside Portunus. That is the only way to exercise a request end to end, since the auth and audit surfaces are Envoy filter callouts rather than routes you can curl.

To run the servicer process on its own — useful for pointing a `grpcurl` / gRPC client at it against a live Redis — from the repo root:

```bash
uv sync
GRPC_ENABLED=true AWS_REGION=eu-west-2 uv run python -m portunus.grpc.server
```

That is the same entry point the container uses (`CMD ["python", "-m", "portunus.grpc.server"]`, also exposed as the `portunus-server` script). It serves ext_authz, ext_proc, `grpc.health.v1.Health` and reflection on `GRPC_PORT`; reflection means a client needs no local `.proto` copy. For logic changes, the unit tests are faster than a live process:

```bash
uv run pytest portunus/tests
```
