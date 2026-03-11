# Proxy Component

Envoy-based reverse proxy that intercepts API requests, retrieves credentials from AWS Secrets Manager via Portunus, and forwards requests with proper authentication.

## Structure

```
proxy/
├── envoy.yaml           # Envoy configuration
├── lua.lua              # Main Lua filter script
├── entrypoint.sh        # Startup script (sets defaults, runs envsubst)
├── Dockerfile           # Proxy container image
├── xray.json            # AWS X-Ray tracing config
└── lib/                 # Lua library and tests
    ├── proxy_utils/     # Reusable Lua modules
    │   ├── init.lua
    │   ├── auth.lua
    │   ├── utils.lua
    │   └── request_signing.lua
    ├── spec/            # Unit tests using pure busted stubs
    ├── Dockerfile.test  # Test container
    └── proxy-utils-1.0-0.rockspec
```

## Request Flow

1. **Client** sends request with special auth header containing AWS credentials + secret ARN
2. **Envoy Lua filter** (`lua.lua`) intercepts request:
   - Extracts auth payload from header
   - Calls Portunus `/authorise` endpoint (with caching)
   - Retrieves real API key from response
   - Replaces auth header with real API key
   - Optionally signs request (Anthropic signature format)
3. **Envoy** forwards modified request to target API
4. **Target API** processes request with real credentials
5. **Envoy** streams response back to client, logging request/response data to Portunus

## Configuration

Configuration is injected via environment variables using `envsubst` in `entrypoint.sh`:

```bash
# Core settings
API_KEY_HEADER=authorization
API_KEY_PREFIX="Bearer "
TARGET_HOST=api.example.com
TARGET_HOST_USE_TLS=true

# Portunus connection
PORTUNUS_HOST=portunus.internal:8080
PORTUNUS_API_KEY=secret-key
PORTUNUS_API_KEY_HEADER=x-api-key

# Optional request signing (Anthropic)
ANTHROPIC_REQUEST_SIGNING_PROVIDER_KEY_ID=provider-key-id
ANTHROPIC_REQUEST_SIGNING_KMS_KEY_ARN=arn:aws:kms:...

# Rate limiting
RATE_LIMIT_PERCENT_ENABLED=0-100
RATE_LIMIT_REQUESTS_PER_INTERVAL=100
RATE_LIMIT_INTERVAL_SECONDS=60
```

See `entrypoint.sh` for full list of environment variables and defaults.

## Lua Library

The `lib/` directory contains a testable Lua library that extracts complex logic from `lua.lua`:

- **`proxy_utils.auth`** - Authentication: extract payloads, call Portunus, send error responses
- **`proxy_utils.utils`** - Utilities: body/header handling, base64 encoding
- **`proxy_utils.request_signing`** - Request signing: compute content digests

### Usage

```lua
-- In lua.lua: create config object (populated via envsubst)
local config = {
  api_key_header = "${API_KEY_HEADER}",
  portunus_host = "${PORTUNUS_HOST}",
  -- ...
}

local proxy_utils = require("proxy_utils")

-- Use library functions
local payload, err = proxy_utils.auth.extract_auth_payload(request_handle, config.api_key_header, config.api_key_prefix)
local headers, body = proxy_utils.auth.call_auth_service(request_handle, payload, digest, config)
```

### Testing

Tests run in Docker using the same `envoyproxy/envoy:v1.31.0` base image as production:

```bash
cd proxy/lib

# Build and run tests
docker build -f Dockerfile.test -t proxy-utils-tests .
docker run --rm proxy-utils-tests
# ●●●●●●●●●●●●●●●●●●●●●●●
# X successes / 0 failures / 0 errors / 0 pending : 0.0Xs
# Exit code 0 on success, 1 on failure

# Show test names (TAP format)
docker run --rm proxy-utils-tests busted -o TAP

# Run specific test file
docker run --rm proxy-utils-tests busted spec/auth_spec.lua

# List all test names
docker run --rm proxy-utils-tests busted --list
```

Unit tests use pure busted stubs to verify library behavior without running Envoy:

```lua
it("should extract auth payload", function()
  local headers_stub = {
    get = stub.new().returns("Bearer token")
  }
  local handle = {
    headers = stub.new().returns(headers_stub)
  }

  local payload, err = portunus_client:extract_auth_payload(handle)

  assert.equals("token", payload)
  assert.is_nil(err)
end)
```

See `lib/spec/README.md` for testing philosophy and guidelines.

### Extending the Library

To add a new module:

1. Create `lib/proxy_utils/new_module.lua`
2. Add to `lib/proxy-utils-1.0-0.rockspec`: `["proxy_utils.new_module"] = "proxy_utils/new_module.lua"`
3. Import in `lib/proxy_utils/init.lua`: `proxy_utils.new_module = require("proxy_utils.new_module")`
4. Rebuild Docker image

## Building

```bash
cd proxy
docker build -t api-key-proxy .
```

The library is installed during build:

```dockerfile
COPY lib /tmp/proxy-utils-lib
WORKDIR /tmp/proxy-utils-lib
RUN luarocks-5.1 make proxy-utils-1.0-0.rockspec
```