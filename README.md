# Portunus

![Portunus](portunus.png)

**Portunus** is a secure API key proxy. It allows clients to authenticate with temporary AWS credentials and transparently swaps them for real API keys stored in AWS Secrets Manager, before forwarding requests to upstream targets. All traffic is logged to Kinesis for auditing.

It consists of two main components:

- **Envoy Proxies**: Envoy deployments (one per target) which interact with the Portunus backend
- **Portunus Backend**: A FastAPI service which authenticates requests using temporary AWS credentials and logs all traffic
  - A client inserts a special payload into the authorization header expected by the upstream API
    - The payload is a base64-encoded JSON blob containing temporary AWS credentials and a reference to a Secrets Manager secret ARN
  - A Lua filter within Envoy forwards this payload to the Portunus `/authorise` endpoint
  - Portunus uses the credentials from the payload to fetch the referenced secret, which should contain the actual API key. Network restrictions prevent clients from doing this directly.
    - Secrets can be stored in two formats:
      - **Plaintext**: `"sk-1234567890abcdef"` (works with any proxy target)
      - **JSON with target validation**: `{"secret":"sk-1234567890abcdef","host":"api.openai.com"}` (only works with matching proxy target)
  - If successful, Portunus returns the real API key to the Envoy instance
  - The filter swaps the original authorization payload for the real API key before allowing the request to proceed
  - If any of the above fails, the connection is terminated and an appropriate response is sent to the client
  - As the above is happening, Envoy also sends request and response data to the Portunus `/log/..` endpoints for storage

Supporting AWS services:

- **Kinesis Data Streams / Firehose**: All traffic is streamed to Kinesis for archival in S3
- **AWS Secrets Manager**: Stores the real API keys
- **AWS X-Ray**: Distributed tracing for debugging

## Data Flow

```mermaid
sequenceDiagram
    participant Client
    participant Envoy as Envoy Proxy
    participant Auth as portunus /authorise
    participant Portunus as portunus /log
    participant Redis
    participant AWS as AWS Services
    participant Target as Upstream Target
    participant Kinesis as AWS Kinesis

    Client->>Envoy: Initial request

    Envoy->>Auth: Call /authorise
    Auth->>Redis: Check for cached auth result

    Auth-->>AWS: (If cache miss) Get AWS Identity
    Auth-->>AWS: (If cache miss) Fetch API Key from SecretManager
    Auth-->>Redis: (If cache miss) Cache successful auth result

    Auth->>Redis: Store principal metadata against request ID
    Auth-->>Envoy: Return auth response

    Note over Envoy: Terminate request if Auth not successful
    Note over Envoy: Substitute API key in request header

    Envoy->>Portunus: Log request headers
    Portunus->>Kinesis: Publish record to Kinesis

    Envoy->>Portunus: Log request body
    Portunus->>Kinesis: Publish record to Kinesis

    Envoy->>Target: Forward request to upstream

    Target-->>Envoy: Stream response
    Envoy-->>Client: Stream response to client

    Envoy->>Portunus: Log response body
    Portunus->>Kinesis: Publish record to Kinesis

    Envoy->>Portunus: Log response headers
    Portunus->>Kinesis: Publish record to Kinesis
```

## Architecture

```mermaid
flowchart TB
    Client["Client Application"]

    Envoy["Envoy Proxy"]

    subgraph "Portunus Service"
        Auth["Portunus /authorise endpoint"]
        LogEndpoint["Portunus /log endpoints"]
    end

    subgraph "External Services"
        Target["Upstream Target Services"]
    end

    subgraph "Data Storage"
        Redis["Redis Cache"]
    end

    subgraph "AWS Services"
        SecretManager["AWS Secret Manager"]
        IAM["AWS IAM/Identity"]
        Kinesis["AWS Kinesis Firehose / S3"]
    end


    %% Client flow
    Client <-->|Request/Response| Envoy

    %% Auth flow
    Envoy -->|Auth Request| Auth
    Auth <-->|Check cache| Redis
    Auth <-->|Identity verification| IAM
    Auth <-->|Fetch API Key| SecretManager
    Auth -->|Store metadata| Redis
    Auth -->|Auth Response| Envoy

    %% Request logging
    Envoy -->|Log events| LogEndpoint

    %% Request forwarding
    Envoy <-->|Forward request/response| Target


    %% Log publishing
    LogEndpoint -->|Archive log| Kinesis

    %% Styling
    classDef client fill:#e6f7ff,stroke:#1890ff
    classDef envoyProxy fill:#f6ffed,stroke:#52c41a
    classDef portunusService fill:#fff7e6,stroke:#fa8c16
    classDef storageLayer fill:#fff2e8,stroke:#fa541c
    classDef awsLayer fill:#fcf4d6,stroke:#d4b106
    classDef externalLayer fill:#f0f5ff,stroke:#2f54eb

    class Client client
    class Envoy envoyProxy
    class Auth,LogEndpoint portunusService
    class Redis storageLayer
    class SecretManager,IAM,Kinesis awsLayer
    class Target externalLayer
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `AWS_REGION` | AWS region for all service clients | *(required)* |
| `PORTUNUS_API_KEY` | Shared secret sent by the proxy and required by Portunus on its service endpoints (`/authorise`, `/log/*`, `/cache/flush`, WebSocket relay). Set the same value on both containers. **Required — Portunus refuses to start without it.** | *(required)* |
| `PORTUNUS_API_KEY_HEADER` | Header carrying the shared secret | `x-api-key` |
| `API_KEY_HEADER` | Header name for the API key | `authorization` |
| `API_KEY_PREFIX` | Prefix for the API key value | `Bearer ` |
| `PORTUNUS_HEADER_PREFIX` | Prefix for proxy response headers (`x-{prefix}-*`) | `portunus` |
| `RATE_LIMIT_PERCENT_ENABLED` | Percentage of traffic to rate limit (0 = disabled) | `0` |
| `RATE_LIMIT_INTERVAL_SECONDS` | Rate limit time window (seconds) | - |
| `RATE_LIMIT_REQUESTS_PER_INTERVAL` | Max requests per interval | - |
| `USE_TLS` / `USE_TLS_TARGET` / `USE_TLS_PROVIDER` / `USE_TLS_LISTENER` | TLS configuration | - |
| `CACHE_DURATION` | Authorization cache TTL | - |
| `CACHE_INACTIVE` | Remove cache entries if unused for this period | - |
| `REDIS_HOST` | Redis hostname | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password | - |
| `REDIS_MAX_CONNECTIONS` | Max Redis connections | `200` |
| `KINESIS_METADATA_STREAM` | Kinesis stream for metadata | - |
| `KINESIS_REQUEST_HEADERS_STREAM` | Kinesis stream for request headers | - |
| `KINESIS_REQUEST_BODY_STREAM` | Kinesis stream for request bodies | - |
| `KINESIS_RESPONSE_HEADERS_STREAM` | Kinesis stream for response headers | - |
| `KINESIS_RESPONSE_BODY_STREAM` | Kinesis stream for response bodies | - |
| `KINESIS_RESPONSE_TRAILERS_STREAM` | Kinesis stream for response trailers | - |

## Local Development

### Setup

```bash
uv sync
```

### Running locally

There is a `docker compose` test rig:

```bash
docker compose up --build
```

By default, the proxy points at an included instance of [httpbun](https://httpbun.com/) which can be used for testing.

Send a request through the stack:

```bash
curl -X GET http://localhost:8888/headers \
  -H "Authorization: Bearer eyJjcmVkZW50aWFscyI6eyJhY2Nlc3Nfa2V5X2lkIjoiQUtJQVRFU1QiLCJzZWNyZXRfYWNjZXNzX2tleSI6IlNFQ1JFVFRFU1QiLCJzZXNzaW9uX3Rva2VuIjoiVEVTVFRPS0VOIn0sInNlY3JldF9hcm4iOiJhcm46YXdzOnNlY3JldHNtYW5hZ2VyOnVzLWVhc3QtMToxMjM0NTY3ODkwMTI6c2VjcmV0OnRlc3Qtc2VjcmV0In0="
```

### Constructing a Payload

You can use `encode_payload()` to construct an authorization payload programmatically:

```python
from portunus.services.payload_service import encode_payload

# credentials dict from STS assume-role or get-session-token
payload = encode_payload(credentials, "arn:aws:secretsmanager:eu-west-2:123456789012:secret:my-api-key")
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with docker compose stack (for e2e tests)
docker compose up --build --wait
uv run pytest tests/ portunus/
```

### X-Ray Integration

For [X-Ray](https://docs.aws.amazon.com/xray/latest/devguide/aws-xray.html) integration to work when testing locally, you need valid credentials in your environment when you start the docker stack. See the compose file for details.

### CloudWatch Integration

For [CloudWatch](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html) integration to work when testing locally, you need to uncomment the logging settings for the relevant services and set valid AWS credentials **in `~/.aws/credentials` for the root user, in the default profile**. See the compose file for details.

## Known Issues

- **Kinesis record size**: Kinesis has a max record size of 1MiB. Large payloads are chunked automatically, but Envoy and Portunus both hold payloads in memory, which may cause memory pressure under heavy load with large payloads.

- **Scaling lag**: The backend autoscales, and some 504/503 responses are expected during rapid load increases. These resolve as the service scales to accommodate the load.

## Streaming

The proxy handles streaming responses (e.g. SSE from LLM APIs) efficiently:
- Request bodies are buffered (up to 50 MiB) for authentication
- Responses are streamed directly to the client as they arrive
- Each response chunk is logged individually with an index
- Envoy's `stream_idle_timeout` is set to 3600s for long-running streams
