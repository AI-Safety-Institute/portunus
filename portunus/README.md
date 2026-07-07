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

## Configuration
The service is configured via environment variables. See `config.py` for a complete list of available options.

Key environment variables:
- `PORTUNUS_API_KEY`, `PORTUNUS_API_KEY_HEADER`: Shared secret (and its header, default `x-api-key`) required on the service endpoints (`/authorise`, `/log/*`, `/cache/flush`, WebSocket relay). Must match the proxy's `PORTUNUS_API_KEY`. Required — the service fails at startup if unset
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: Redis connection settings
- `CACHE_DURATION`: How long to cache authorization responses (seconds)
- `LOG_TTL`: How long to store log data in Redis (seconds)
- `AWS_ENDPOINT_URL`: Can be used pointed at a localstack instance to avoid hitting AWS

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
