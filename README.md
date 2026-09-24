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
    - Secrets can be stored in three formats (see [Secret formats](#secret-formats)):
      - **Plaintext**: `"sk-1234567890abcdef"` (works with any proxy target)
      - **JSON with target validation**: `{"secret":"sk-1234567890abcdef","host":"api.openai.com"}` (only works with matching proxy target)
      - **Minted token**: `{"type":"anthropic_wif", ...}`, `{"type":"openai_wif", ...}` or `{"type":"gcp_wif", ...}` (no key is stored; Portunus mints a short-lived token per caller)
  - If successful, Portunus returns the real API key to the Envoy instance
  - The filter swaps the original authorization payload for the real API key (in the header named by the `/authorise` response, or `API_KEY_HEADER` by default), removing the `API_KEY_HEADER` header when the two differ, before allowing the request to proceed. Every other header is forwarded untouched
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

    Auth->>Kinesis: Publish principal metadata
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
    Auth -->|Publish metadata| Kinesis
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

## Security Model

Portunus's service endpoints (`/authorise`, `/log/{request_id}/...`, `/cache/flush`, and the WebSocket relay) **do not authenticate their callers**. Anything that can reach them directly can flush the auth cache (forcing all clients to re-authenticate) or inject records into the Kinesis audit trail under any request ID. Only `/ping` is intended to be reachable without protection (health checks).

The Envoy proxy already sends a shared secret with every call it makes to Portunus: `PORTUNUS_API_KEY`, carried in the `PORTUNUS_API_KEY_HEADER` header (default `x-api-key`). Portunus itself does not validate it, so your deployment **must** enforce access in front of the service:

- **Validate the shared-secret header before requests reach Portunus.** We recommend an authenticating reverse-proxy sidecar (e.g. nginx) in front of the service: reject any request that doesn't carry the expected `x-api-key` value and forward the rest (including WebSocket upgrades) to the app, exposing only the sidecar's port.
- **And/or restrict network reachability** so that only the Envoy proxies (and trusted operational tooling, e.g. whatever calls `/cache/flush`) can reach the Portunus service at all.

Do not expose Portunus directly to clients or the public internet.

### Logged data

Portunus captures **full request and response data** — bodies, headers, and trailers — and publishes it to Kinesis for the audit trail. This is deliberate: the logs are an audit record of everything that passed through the proxy. Be aware that this means:

- **Request and response bodies are stored verbatim**, including prompts, completions, and any data (personal, commercial, or otherwise sensitive) that clients send or receive.
- **Headers and URLs are stored verbatim**, except the headers that can carry a credential: the provider API key header (`API_KEY_HEADER`), the header the real upstream credential is injected into, and every name in `KNOWN_AUTH_HEADERS`. These are dropped before logging. No other headers are filtered — secrets carried in any *other* header, or embedded in a URL or body, **will be captured**.

Portunus does **not** attempt to redact secrets or sensitive content from what it logs. If you need redaction, filtering, or access tiering, do it downstream of the Kinesis streams (e.g. in the ETL/query layer that consumes the logs) and restrict who can read the raw stream output. Treat the raw log storage as containing everything your clients send and receive.

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `AWS_REGION` | AWS region for all service clients | *(required)* |
| `PORTUNUS_API_KEY` | Shared secret the proxy attaches to every Portunus service call, in the `PORTUNUS_API_KEY_HEADER` header. Portunus does not validate it — see [Security Model](#security-model) | - |
| `PORTUNUS_API_KEY_HEADER` | Header carrying the shared secret | `x-api-key` |
| `API_KEY_HEADER` | Header name for the API key | `authorization` |
| `API_KEY_PREFIX` | Prefix for the API key value | `Bearer ` |
| `KNOWN_AUTH_HEADERS` | Comma-separated header names excluded from header logging, in addition to `API_KEY_HEADER` and the header the credential is written to. Does not affect which headers are forwarded | `authorization,x-api-key,x-goog-api-key,api-key` |
| `PORTUNUS_HEADER_PREFIX` | Prefix for proxy response headers (`x-{prefix}-*`) | `portunus` |
| `RATE_LIMIT_PERCENT_ENABLED` | Percentage of traffic to rate limit (0 = disabled) | `0` |
| `RATE_LIMIT_INTERVAL_SECONDS` | Rate limit time window (seconds) | - |
| `RATE_LIMIT_REQUESTS_PER_INTERVAL` | Max requests per interval | - |
| `USE_TLS` / `USE_TLS_TARGET` / `USE_TLS_PROVIDER` / `USE_TLS_LISTENER` | TLS configuration | - |
| `CACHE_DURATION` | Authorization cache TTL (seconds) | `86400` |
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
| `FEDERATION_ALLOWED_ACCOUNT_IDS` | Comma-separated AWS account IDs whose federation roles a secret may name. Unset disables token minting | - |
| `FEDERATION_ROLE_PATH_PREFIX` | IAM path federation role ARNs must start with | `/portunus-fed/` |
| `FEDERATION_STS_ENDPOINT_URL` | STS endpoint for federation calls. Defaults to `AWS_ENDPOINT_URL` if set, else `https://sts.<region>.amazonaws.com` | - |
| `FEDERATION_USER_TAG_KEY` | Session tag key carrying the user on identity tokens: the caller's STS source identity, or its IAM role name when the session has none | `portunus:user` |
| `FEDERATION_PRINCIPAL_TAG_KEY` | Session tag key carrying the caller's IAM role name on identity tokens | `portunus:principal` |
| `FEDERATION_SESSION_TAG_KEY` | Session tag key carrying the caller's role session name on identity tokens | `portunus:session` |
| `FEDERATION_PROJECT_TAG_KEY` | Session tag key carrying the caller's project on identity tokens | `portunus:project` |

### Secret formats

A secret referenced by a payload is one of:

| Format | Example | Behaviour |
|---|---|---|
| Plaintext | `sk-1234567890abcdef` | Used as the key for any target |
| Stored key with target check | `{"secret": "sk-...", "host": "api.example.com"}` | Used only when the proxy's target matches `host` |
| Minted token | `{"type": "anthropic_wif", ...}`, `{"type": "openai_wif", ...}` or `{"type": "gcp_wif", ...}` (below) | No key is stored; a short-lived token is minted per caller |

JSON without a `type` is treated as a stored key (and, if it does not match that schema, used verbatim as the key); a typeless object with a `federation_role_arn` is a mint secret missing its `type` and is rejected rather than used as a key. JSON with a `type` must validate as that type; `static` names the stored-key form explicitly.

#### `anthropic_wif`

```json
{
  "type": "anthropic_wif",
  "host": "api.anthropic.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/projects/example/example-grant@projects.example",
  "federation_rule_id": "fdrl_01EXAMPLE",
  "organization_id": "11111111-1111-4111-8111-111111111111",
  "service_account_id": "svac_01EXAMPLE",
  "workspace_id": "wrkspc_01EXAMPLE",
  "audience": "https://api.anthropic.com"
}
```

`audience` (default shown) is optional; unknown fields are rejected. On a cache miss Portunus:

1. Verifies the caller with STS and fetches the secret, as for stored keys.
2. Checks `federation_role_arn` is `arn:aws:iam::<account>:role<FEDERATION_ROLE_PATH_PREFIX><name>` with `<account>` in `FEDERATION_ALLOWED_ACCOUNT_IDS`; `<name>` is any further IAM path plus the role name. Nothing else is called if this fails.
3. Assumes the federation role with the caller's own credentials (`RoleSessionName` is the caller's IAM role name) through the regional STS endpoint, then from that session requests an STS web identity token for `audience`, tagged with the user (`FEDERATION_USER_TAG_KEY`: the caller's STS source identity if its session carries one, else its IAM role name), the caller's IAM role name (`FEDERATION_PRINCIPAL_TAG_KEY`), its role session name (`FEDERATION_SESSION_TAG_KEY`) and its project (`FEDERATION_PROJECT_TAG_KEY`). A service acting for a user sets `SourceIdentity` when assuming its own role, so the user tag names that user while the principal tag names the service's role and the session tag its acting session.
4. Exchanges the token at `https://api.anthropic.com/v1/oauth/token` (RFC 7523 JWT bearer grant, with the four identifiers above) and returns the bearer token with `output_header: "authorization"` and `output_prefix: "Bearer "`.

If STS or the token endpoint cannot be reached or answers 5xx/429, or steps 3–4 take longer than 6 s, `/authorise` returns 503 rather than 403.

Every exchange uses a freshly issued STS token.

#### `openai_wif`

```json
{
  "type": "openai_wif",
  "host": "api.openai.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/projects/example/example-grant@projects.example",
  "identity_provider_id": "idp_01EXAMPLE",
  "service_account_id": "svc_acct_01EXAMPLE",
  "audience": "https://api.openai.com/v1"
}
```

`audience` (default shown) is optional and must equal the audience configured on the OpenAI workload identity provider `identity_provider_id`; `service_account_id` is the OpenAI service account the token acts as. Service accounts created in the dashboard may show a `user-…` id rather than `svc_acct_…`; either is accepted. Both ids are `[A-Za-z0-9_-]+`. Steps 1–3 are as for `anthropic_wif`, except that the STS token is signed with ES384 rather than RS256 (OpenAI's documented preference); then Portunus:

4. Exchanges the token at `https://auth.openai.com/oauth/token` (RFC 8693 token exchange; JSON body with `grant_type` `urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` `urn:ietf:params:oauth:token-type:jwt`, `subject_token`, `identity_provider_id` and `service_account_id`) and returns `access_token` with `output_header: "authorization"` and `output_prefix: "Bearer "`. Expiry comes from `expires_in`.

OpenAI issues the access token for at most an hour and never beyond the STS token's expiry, so Portunus requests a 30-minute STS token here (`anthropic_wif` requests 15 minutes, which Anthropic doubles) and the access token lives about 30 minutes and is cached for about 29. As for `anthropic_wif`, an unreachable endpoint, a 5xx/429 answer or a missed 6 s deadline returns 503.

On the OpenAI side, all deployment concerns: the federation role's account must have outbound web identity federation enabled, and the workload identity provider's OIDC issuer is that account's STS issuer URL, with `audience` as its audience. The service account mapping matches the token's `sub`, which is the federation role's IAM ARN (`federation_role_arn`). The four Portunus tags arrive as `request_tags` under the `https://sts.amazonaws.com/` claim and can be matched through a CEL attribute transformation such as `assertion["https://sts.amazonaws.com/"]["request_tags"]["portunus:user"]`. The federation role's identity policy must allow `sts:GetWebIdentityToken` for `audience` with `sts:DurationSeconds` of at least 1800; OpenAI's example policy caps it at 300.

#### `gcp_wif`

```json
{
  "type": "gcp_wif",
  "host": "aiplatform.googleapis.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/projects/example/example-grant@projects.example",
  "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-provider",
  "service_account": "example-sa@example-project.iam.gserviceaccount.com",
  "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
  "token_lifetime_seconds": 3600
}
```

`scopes` (default shown) and `token_lifetime_seconds` (600–3600, default 3600) are optional. `audience` must be a pool provider resource name in the form shown and `service_account` an email address. Steps 1–3 are as for `anthropic_wif`, with the STS token (RS256, 15 minutes) requested for `audience`; then Portunus:

4. Exchanges the token at `https://sts.googleapis.com/v1/token` (RFC 8693 token exchange; form-encoded body with `grant_type` `urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` `urn:ietf:params:oauth:token-type:jwt`, `subject_token`, `audience`, `scope` `https://www.googleapis.com/auth/iam` and `requested_token_type` `urn:ietf:params:oauth:token-type:access_token`) for a federated token, then calls `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<service_account>:generateAccessToken` with `scopes` and `token_lifetime_seconds`. The access token is returned with `output_header: "authorization"` and `output_prefix: "Bearer "`. Expiry comes from `expireTime`.

As for `anthropic_wif`, an unreachable Google endpoint, a 5xx/429 answer or a missed 6 s deadline returns 503.

On the Google side, all deployment concerns: the workload identity pool provider is an OIDC provider whose issuer is the federation role's account's STS issuer URL and whose allowed audience is the provider's own resource name, the secret's `audience`. The token's `sub` is the federation role's IAM ARN including its path (`federation_role_arn`), so the attribute mapping derives `google.subject` from `assertion.sub` with an `extract` that keeps it within Google's 127-character subject limit, and the attribute condition matches the role path prefix. The four Portunus tags arrive as `request_tags` under the `https://sts.amazonaws.com/` claim and are available to the attribute mapping, e.g. `assertion['https://sts.amazonaws.com/']['request_tags']['portunus:user']`. The service account must grant `roles/iam.workloadIdentityUser` to the pool principal the mapping produces. The federation role's identity policy must allow `sts:GetWebIdentityToken` for `audience` and `sts:TagGetWebIdentityToken` for the four tag keys, as for the other minted types.

#### Caching and the federation role

Unlike stored keys, which are cached for `CACHE_DURATION`, a minted token is cached until the earlier of `CACHE_DURATION` and one minute before the token expires. Concurrent cache misses for one payload and target share a single mint per Portunus process.

The federation role itself (trust policy, identity policy, who may assume it) is a deployment concern, as is how roles under the prefix are named. The secret names the role; Portunus checks the account and prefix and assumes exactly that role. To issue the identity token, the role's identity policy must allow `sts:GetWebIdentityToken` for the secret's `audience` (`sts:IdentityTokenAudience`) and, because Portunus always passes `Tags`, `sts:TagGetWebIdentityToken` with `aws:TagKeys` covering the four configured tag keys (`FEDERATION_*_TAG_KEY`). The CLI's default session policy allows `sts:AssumeRole` on the whole prefix, `arn:aws:iam::<caller account>:role/portunus-fed/*`, so which roles a caller can actually assume is bounded by the caller's own identity policy and each role's trust policy. Pass `--federation-role-path` if the deployment uses a different path. The CLI assumes the caller's own role with `RoleSessionName` `portunus`; pass `--session-name` when that role's trust policy only admits a particular session name.

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
payload = encode_payload(
    credentials, "arn:aws:secretsmanager:eu-west-2:123456789012:secret:my-api-key"
)
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
