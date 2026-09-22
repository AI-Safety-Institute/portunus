# Portunus

## Overview
This package implements the Portunus service for the API Key Proxy system. It handles API key management, authorization, and request/response logging.

## Architecture
The service follows a modular architecture with the following components:

### Core Components
- **FastAPI Application** (`app.py`): Defines the API endpoints and routes requests to the appropriate service methods.
- **Configuration** (`config.py`): Centralized configuration management using Pydantic.
- **Services**: Business logic modules implementing core functionality:
  - `auth_service.py`: Authentication and authorization logic
  - `secrets_service.py`: Secrets management and AWS integration
  - `logging_service.py`: Request/response logging
- **State Management** (`state/`): Redis-based state management for caching and logging:
  - `base.py`: Core Redis client management
  - `cache.py`: API key caching functionality
  - `logs.py`: Request/response log storage
  - `stats.py`: Statistics and metrics collection

### Data Models
- **Models** (`models.py`): Pydantic data models for request/response objects
- **Types** (`types.py`): Type definitions and type aliases
- **Exceptions** (`exceptions.py`): Custom exception classes

## Key Features
- Securely retrieve API keys from AWS Secrets Manager
- Cache API key responses for improved performance
- Log request and response data for auditing
- Track principal identity information
- Support mock mode for development/testing

## Security
The service endpoints (`/authorise`, `/log/*`, `/cache/flush`, WebSocket relay) do not authenticate their callers. The proxy sends a shared secret (`PORTUNUS_API_KEY`, header `x-api-key` by default) with every call, but this service does not check it — deployments must validate it in front of the service (e.g. an authenticating reverse-proxy sidecar) and/or restrict network reachability to the proxies.

The `/log/*` endpoints capture full request/response bodies, headers, and trailers verbatim (everything except the provider API key header) — no secret redaction is performed here; do any redaction downstream of Kinesis. See the [Security Model](../README.md#security-model) section of the root README for both points.

## Configuration
The service is configured via environment variables. See `config.py` for a complete list of available options.

Key environment variables:
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: Redis connection settings
- `CACHE_DURATION`: How long to cache authorization responses (seconds)
- `LOG_TTL`: How long to store log data in Redis (seconds)
- `AWS_ENDPOINT_URL`: Can be used pointed at a localstack instance to avoid hitting AWS

### gRPC publisher tuning

The gRPC publisher accepts these optional settings:

| Environment variable | Default | Allowed range |
| --- | --- | --- |
| `GRPC_PUBLISH_WORKERS` | `max(4, GRPC_MAX_CONCURRENT_STREAMS // 64)` | 1–64 when set |
| `GRPC_PUBLISH_BATCH_SIZE` | 500 records | 1–3000 |
| `GRPC_PUBLISH_COALESCE_MS` | 0 milliseconds | 0–100, finite |

The batch size groups queued records across destinations. Individual Firehose
requests still obey the 500-record and 4-MiB limits. Coalescing pauses between
partial batches, adding up to the configured delay for new arrivals.
Queue record and payload-byte limits continue to apply.

One worker, 3000 records and 5 milliseconds passed synthetic throughput tests.
This profile is opt-in: validate destination fairness, retry behaviour and oldest
record age with the intended audit sinks before adopting it. Leaving these
variables unset preserves the existing publisher defaults.

## Development
From the repository root, install dependencies:
```bash
uv sync
```

Run the service locally:
```bash
cd portunus
uv run uvicorn portunus.app:app --reload
```

## Testing
Run tests with pytest:
```bash
uv run pytest
```
