# Portunus (backend package)

The `portunus/` Python package is the gRPC servicer process that Envoy delegates auth and audit to. The root [README](../README.md) covers the overall system; this README is the dev-facing map of the package and how to run its unit tests.

For architecture and request flow (ext_authz `Check`, the composite-filter signing pass, ext_proc `Process`), see the [repo-root `CLAUDE.md`](../CLAUDE.md).

## Module map

```
portunus/
  app.py            FastAPI app: operator endpoints (/ping, /cache/flush) and
                    gRPC server lifecycle via the lifespan context manager.
  cli.py            Console entry point.
  config.py         Env-driven PortunusConfig (singleton at import time).
  exceptions.py     Service exception types (AuthenticationError, CredentialsError, ...).
  logging.py        Access-log middleware and logger configuration.
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
    publish_queue.py     Bounded async queue with headroom reserved for metadata
                         vs body submits.
    proxy_auth.py        Server interceptor validating x-portunus-proxy-key on
                         the initial metadata.

  services/
    auth_service.py            STS get-caller-identity + Secrets Manager fetch +
                               target-host validation, cached via CacheService.
    secrets_service.py         aiobotocore Secrets Manager client; boto_session
                               is constructor-injectable for tests.
    cache_service.py           Redis-backed auth-response cache (key = sha256(payload)).
    signing_service.py         RFC 9421 (HTTP Message Signatures) over AWS KMS.
                               KMS.Sign is sync boto3 offloaded via asyncio.to_thread.
    publish_service.py         Firehose publish helpers; one method per record type.
    state_service.py           Redis client lifecycle.
    payload_service.py         Base64 / JSON payload encode/decode.
    arn_service.py             Secret ARN parsing.
    secret_validation_service.py  Secret-shape validation (plaintext vs JSON, target host).
    xray_service.py            X-Ray tracing helpers.
```

## gRPC-service environment variables

These gate the servicer process specifically; the root README documents the rest.

| Variable | Purpose |
|---|---|
| `GRPC_ENABLED` | Start the ext_authz + ext_proc server (default `false`). |
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

The intended entry point is the full stack (`docker compose up --build` at the repo root), which brings up Envoy, Redis, LocalStack, and an httpbun upstream alongside Portunus. To run just the FastAPI app — useful for poking `/ping` or `/cache/flush` against a live Redis — from the repo root:

```bash
uv sync
cd portunus && uv run uvicorn portunus.app:portunus --reload
```

Set `GRPC_ENABLED=false` if you don't want the gRPC server bound on the same process.
