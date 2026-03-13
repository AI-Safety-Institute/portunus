# Portunus

## Overview
This repo implements a secure API key proxy system with two main components:
- **Proxy**: Envoy-based reverse proxy that forwards API requests with optional request signing
- **Portunus**: FastAPI service that handles API key management, authorization, and Redis-based caching

## Key Functionality
- Securely retrieve API keys via pluggable auth backends (AWS Secrets Manager by default)
- Transparently proxy requests to third-party APIs (like OpenAI)
- Log request and response data via pluggable stream publishers (Kinesis by default)
- Configurable rate limiting at the proxy level
- Caching of authorization responses to improve performance
- TLS support for secure communications
- Request ID tracking throughout the system
- Principal identity tracking for audit purposes

## Detailed Data Flow

### Authentication Flow
1. Client makes request with a special authorization header: `Authorization: Bearer <base64-encoded-payload>`
   - The payload contains AWS credentials and a secret ARN
   - Format: `API_KEY_PREFIX + base64(json({"credentials": {...}, "secret_arn": "..."}))`
   - This can be generated using `api_key_override()` in `util.py` which takes a secret ARN in format `aws-secretsmanager://<secret-arn>` and returns the encoded payload
2. Envoy proxy intercepts the request via Lua script (`lua.lua`)
   - Extracts the `Authorization` header
   - Removes the Bearer prefix from the payload
   - Makes a synchronous call to `/authorise` endpoint
   - Passes the extracted payload in the request body: `{"authorization": "<payload>"}`
3. Portunus (`app.py` → `services.auth_service` → `AuthService.authenticate`):
   - Checks Redis cache first (keyed by SHA-256 of payload)
   - If cached, returns stored API key immediately (faster responses)
   - If not cached, delegates to the configured auth backend:
     - **AWS backend** (`backends/aws/auth.py`): Decodes base64 payload, calls STS for identity, fetches secret from Secrets Manager
     - Identity parsing uses a configurable regex (`AWS_IDENTITY_ROLE_PATTERN`) for project extraction from role names
   - Publishes metadata (principal info) via configured stream publisher for audit trail
   - Returns formatted API key with principal info
4. Proxy replaces original authorization header with actual API key
   - `request_handle:headers():replace(API_KEY_HEADER, api_key)`
   - For testing compatibility, the Bearer prefix is not added to the API key
5. Proxy forwards the modified request to target API
6. Target API processes request using the real API key

### Logging Flow
1. Request logging:
   - Proxy captures request headers and body before forwarding
   - Makes async call to `/log` with metadata and type "request_headers", "request_body", or "request_trailers"
   - Payload is validated against appropriate Pydantic models (defined in `models.py`)
   - Binary data is base64-encoded by Lua before being sent to Portunus
   - Portunus publishes events directly to Kinesis Data Streams for long-term storage
2. Response logging:
   - After receiving upstream response, Lua captures response data
   - Makes async call to `/log` with metadata and type "response_headers", "response_chunk", or "response_trailers"
   - Each log event is typed based on its content (e.g., `ResponseChunkEvent` includes `chunk` and `index`)
   - Binary data is base64-encoded by Lua before being sent to Portunus
   - Portunus publishes events directly to Kinesis Data Streams for long-term storage
3. Metadata publishing:
   - Principal identity information is published to Kinesis during the authorization phase
   - All log events are published directly to separate Kinesis Data Streams (metadata, request headers/body/trailers, response headers/body/trailers)
   - No intermediate Redis storage is used for log data

A unique request ID is generated for each request and used to tie all logs together for traceability.

### Streaming Response Handling
The proxy is designed to handle streaming responses efficiently:
1. The proxy buffers the entire request body (configured up to 50 MiB) to authenticate it properly
2. Responses, however, are streamed directly to the client as they arrive
3. For streaming responses like SSE (Server-Sent Events), each chunk is logged individually with an index
4. Envoy's stream_idle_timeout is increased to 3600s to support long-running streaming responses
5. Response chunks are captured asynchronously to minimize impact on streaming performance

## Configuration

### Environment Variables

#### Backend Selection
- `PORTUNUS_AUTH_BACKEND`: Auth backend (default: "aws")
- `PORTUNUS_LOG_BACKEND`: Log publishing backend (default: "kinesis", also: "debug")

#### AWS Backend
- `AWS_IDENTITY_ROLE_PATTERN`: Regex with named groups for extracting project from role names (e.g. `^UserProfile_[^_]+_(?P<project>.+)$`)
- `AWS_ENDPOINT_URL`: Override AWS endpoint for LocalStack testing

#### General
- `API_KEY_HEADER`: Header name to use for API key (default: "authorization")
- `API_KEY_PREFIX`: Prefix for API key (default: "Bearer ")
- `RATE_LIMIT_PERCENT_ENABLED`: Enable rate limiting (0-100 percentage of traffic)
- `RATE_LIMIT_INTERVAL_SECONDS`: Time window for rate limiting (seconds)
- `RATE_LIMIT_REQUESTS_PER_INTERVAL`: Maximum number of requests allowed per interval
- `RATE_LIMIT_PERCENT_ENABLED=0` disables rate limiting entirely
- When rate-limited, the proxy returns a 429 status code with an `x-{PORTUNUS_HEADER_PREFIX}-rate-limit: true` header (default prefix: `portunus`)
- `USE_TLS`, `USE_TLS_TARGET`, `USE_TLS_PROVIDER`, `USE_TLS_LISTENER`: TLS configuration
- `CACHE_DURATION`: How long to cache authorization responses
- `CACHE_INACTIVE`: Remove cache entries if unused for this period
- `REDIS_HOST`: Hostname for Redis server (used for authorization caching)
- `REDIS_PORT`: Port for Redis server (default: 6379)
- `REDIS_PASSWORD`: Password for Redis authentication
- `REDIS_MAX_CONNECTIONS`: Maximum number of Redis connections

## Development
- Root project includes all dependencies: `uv sync`
- Run tests: `uv run pytest`
- Local testing with docker-compose: `docker compose up --build --wait`

## Important Files
- `/portunus/portunus/app.py` - Main FastAPI application with endpoints
- `/portunus/portunus/backends/protocols.py` - Protocol definitions for pluggable backends (AuthBackend, StreamPublisher)
- `/portunus/portunus/backends/__init__.py` - Backend factory functions
- `/portunus/portunus/backends/aws/auth.py` - AWS auth backend (STS + Secrets Manager + KMS signing)
- `/portunus/portunus/backends/aws/identity.py` - Configurable ARN identity parsing
- `/portunus/portunus/backends/aws/publisher.py` - Kinesis stream publisher
- `/portunus/portunus/backends/debug/publisher.py` - Debug publisher for development
- `/portunus/portunus/services/auth_service.py` - Auth orchestrator with caching (delegates to AuthBackend)
- `/portunus/portunus/services/publish_service.py` - Record construction + delegation to StreamPublisher
- `/portunus/portunus/util.py` - Utility functions and helpers
- `/portunus/portunus/models.py` - Data models and schemas
- `/portunus/portunus/config.py` - Configuration management
- `/proxy/lua.lua` - Lua script for request/response interception and modification
- `/proxy/envoy.yaml` - Envoy proxy configuration
- `/proxy/entrypoint.sh` - Script for TLS and environment variable configuration

## Testing Commands
```bash
# Run all tests
uv run pytest

# Test specific component
uv run pytest tests/test_e2e.py
```

