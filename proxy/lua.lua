-- Import proxy utilities library
local proxy_utils = require("proxy_utils")
local utils = proxy_utils.utils
local request_signing = proxy_utils.request_signing
local logging = proxy_utils.logging

-- Configuration object populated by environment variables during startup (via envsubst)
-- This is the only place where envsubst placeholders should appear
local config = {
	api_key_header = "${API_KEY_HEADER}",
	api_key_prefix = "${API_KEY_PREFIX}",
	portunus_host = "${PORTUNUS_HOST}",
	portunus_api_key = "${PORTUNUS_API_KEY}",
	portunus_api_key_header = "${PORTUNUS_API_KEY_HEADER}",
	target_host = "${TARGET_HOST}",
	target_host_use_tls = "${TARGET_HOST_USE_TLS}",
	header_prefix = "${PORTUNUS_HEADER_PREFIX}",
	cors_allowed_origins = "${CORS_ALLOWED_ORIGINS}",
}

-- Parse CORS allowed origins. Supports exact origins and prefix wildcard domains
-- (e.g. "*.example.com" matches "https://hub.apps.example.com").
-- Only "*.domain" wildcards are supported — wildcards in other positions are treated as literals.
-- Empty string means CORS is disabled (backwards compatible).
local cors_exact = {}
local cors_wildcard_suffixes = {}
local cors_enabled = false
if config.cors_allowed_origins ~= "" then
	for origin in config.cors_allowed_origins:gmatch("[^,]+") do
		local trimmed = origin:match("^%s*(.-)%s*$")
		if trimmed ~= "" then
			cors_enabled = true
			if trimmed:sub(1, 2) == "*." then
				-- "*.example.com" → match any origin whose host ends with ".example.com"
				cors_wildcard_suffixes[#cors_wildcard_suffixes + 1] = trimmed:sub(2)  -- ".example.com"
			else
				cors_exact[trimmed] = true
			end
		end
	end
end

--- Returns the origin if it is allowed, or nil if not.
local function get_allowed_origin(request_handle)
	if not cors_enabled then
		return nil
	end
	local origin = request_handle:headers():get("origin")
	if not origin then
		return nil
	end
	if cors_exact[origin] then
		return origin
	end
	-- Extract host from origin (e.g. "https://hub.apps.example.com" → "hub.apps.example.com")
	local host = origin:match("^https://([^:/]+)")
	if host then
		for _, suffix in ipairs(cors_wildcard_suffixes) do
			if host:sub(-#suffix) == suffix then
				return origin
			end
		end
	end
	return nil
end

-- Instantiate Portunus client with configuration
local portunus = proxy_utils.portunus.new(config)

-- Headers excluded from request/response header logging: the fixed
-- credential denylist plus this proxy's configured api_key_header
local sensitive_log_headers = utils.sensitive_headers({ config.api_key_header })

function envoy_on_request(request_handle)
	-- Main function that processes incoming requests
	-- 1. Handles /ping health check requests
	-- 2. Buffers full request body
	-- 3. Computes content digest for request signing
	-- 4. Extracts authorization payload from headers
	-- 5. Calls Portunus service to retrieve real API key
	-- 6. Handles errors from Portunus service
	-- 7. Replaces authorization header with real API key
	-- 8. Adds Content-Digest and Signature headers if applicable
	-- 9. Logs request body, headers, and trailers

	-- Handle /ping health check requests without authorization
	if request_handle:headers():get(":path") == "/ping" then
		request_handle:respond({
			[":status"] = "200",
			["x-" .. config.header_prefix .. "-ping"] = "true",
		}, "healthy")
		return
	end

	-- Skip Lua processing for WebSocket upgrade requests.
	-- The WS route also disables Lua via typed_per_filter_config in envoy.yaml,
	-- but this check is kept as a safety net.
	local upgrade_header = request_handle:headers():get("upgrade")
	if upgrade_header and upgrade_header:lower() == "websocket" then
		return
	end

	-- Handle CORS preflight (OPTIONS) requests
	local allowed_origin = get_allowed_origin(request_handle)
	if request_handle:headers():get(":method") == "OPTIONS" and allowed_origin then
		local requested_headers = request_handle:headers():get("access-control-request-headers") or ""
		request_handle:respond({
			[":status"] = "204",
			["access-control-allow-origin"] = allowed_origin,
			["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS",
			["access-control-allow-headers"] = requested_headers,
			["access-control-max-age"] = "3600",
			["vary"] = "Origin",
		}, "")
		return
	end

	-- Store allowed origin in metadata for the response handler
	if allowed_origin then
		request_handle:streamInfo():dynamicMetadata():set(
			"envoy.filters.http.lua", "cors_origin", allowed_origin
		)
	end

	-- Process the request with error handling
	local ok, error = pcall(function()
		-- Get full request body - we need to buffer the entire request
		-- because we must authorize it before forwarding
		-- TODO: It would be nice if we could buffer for only as long as authorisation takes,
		-- but Envoy Lua filter doesn't support async body reading.
		local full_request_body = utils.get_full_request_body(request_handle)
		local content_digest = request_signing.compute_content_digest(request_handle, full_request_body)

		-- Note on header modification timing:
		-- From Envoy docs: Headers can be modified only after an httpCall() or body() returns.
		-- See: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/lua_filter#headers
		-- The script will fail if headers are modified at other times.

		-- Set scheme based on USE_TLS environment variable.
		-- The url (scheme, authority, path) must be finalised before request signing
		-- (if used), because the url is part of the signature.
		if config.target_host_use_tls == "true" then
			request_handle:headers():replace(":scheme", "https")
			request_handle:headers():replace(":authority", config.target_host)
		end

		-- Extract authorization payload from headers (removes Bearer prefix)
		local auth_payload, err = portunus:extract_auth_payload(request_handle)
		if err then
			-- If no valid authorization header, return 401
			-- No trace ID is available at this point
			portunus:send_error_response(request_handle, 401, err, "unknown", allowed_origin)
			return
		end

		-- Make synchronous call to Portunus service to get the real API key
		local headers, body = portunus:authorise(request_handle, auth_payload, content_digest)

		-- If headers are nil, then there was some kind of network error
		if not headers then
			portunus:send_error_response(request_handle, 502, "Authorization service unreachable", "unknown", allowed_origin)
			return
		end

		-- Handle non-200 responses from the auth service
		if headers[":status"] ~= "200" then
			-- Pass through auth service errors with appropriate status code
			local error_message, request_id = portunus:parse_error_response(body)
			portunus:send_error_response(request_handle, headers[":status"], error_message, request_id, allowed_origin)
			return
		end

		-- Otherwise, parse successful authorization response
		local auth_response, err = portunus:parse_authorization_response(body)
		if err then
			portunus:send_error_response(request_handle, 500, err, "unknown", allowed_origin)
			return
		end

		-- Store the request_id in dynamic metadata for retrieval during response processing
		-- Presence of this ID indicates a successful authorization
		request_handle
			:streamInfo()
			:dynamicMetadata()
			:set("envoy.filters.http.lua", "request_id", auth_response.request_id)

		-- Replace the authorization header with the real API key retrieved from Secrets Manager
		-- Note: The header originally contained config.api_key_prefix + auth payload
		request_handle:headers():replace(config.api_key_header, config.api_key_prefix .. auth_response.api_key)

		-- Add Content-Digest and Signature headers if present
		request_handle:headers():replace("Content-Digest", content_digest)
		if auth_response.signature and auth_response.signature_input then
			request_handle:headers():replace("Signature", auth_response.signature)
			request_handle:headers():replace("Signature-Input", auth_response.signature_input)
		end

		-- Log the request body
		portunus:log_request_body(request_handle, auth_response.request_id, full_request_body)

		-- Log request headers, excluding credential-carrying headers
		local request_headers = {}
		for k, v in pairs(request_handle:headers()) do
			if not utils.is_sensitive_header(k, sensitive_log_headers) then
				request_headers[k] = v
			end
		end
		portunus:log_request_headers(
			request_handle,
			auth_response.request_id,
			utils.convert_pairs_to_table(request_handle, request_headers)
		)

		-- Log request trailers
		local req_trailers = utils.convert_pairs_to_table(request_handle, request_handle:trailers() or {})
		portunus:log_request_trailers(request_handle, auth_response.request_id, req_trailers)
	end)

	if not ok then
		logging.err(request_handle, "ERROR: " .. error)
		portunus:send_error_response(request_handle, 500, "Internal proxy error", "unknown", allowed_origin)
	end
end

function envoy_on_response(response_handle)
	-- Main function that processes responses from the upstream API
	-- 1. Retrieves the request_id from metadata if authorization succeeded
	-- 2. Exits early if no request_id (no logging for unauthenticated requests)
	-- 3. Adds trace ID header to the response
	-- 4. Buffers full response body without interrupting streaming to client
	-- 5. Logs response body, headers, and trailers

	local ok, error = pcall(function()
		-- Get metadata stored during request processing
		local metadata = response_handle:streamInfo():dynamicMetadata():get("envoy.filters.http.lua")
		local request_id = nil
		local cors_origin = nil
		if metadata then
			request_id = metadata["request_id"]
			cors_origin = metadata["cors_origin"]
		end

		-- Add CORS headers if the request origin was allowed
		if cors_origin then
			response_handle:headers():replace("access-control-allow-origin", cors_origin)
			response_handle:headers():replace("vary", "Origin")
		end

		if not request_id then
			-- If no request_id, skip logging silently
			-- This happens for /ping requests and other direct responses
			return
		end

		-- Add trace ID to response headers for debugging and correlation
		response_handle:headers():add("X-Amzn-Trace-Id", request_id)

		-- Buffer the entire response body in memory
		-- This still allows streaming to the client but simplifies logging
		local complete_response_body = ""

		for chunk in response_handle:bodyChunks() do
			complete_response_body = complete_response_body .. chunk:getBytes(0, chunk:length())
		end

		-- Log the complete response body (after chunking)
		logging.info(response_handle, "Logging complete response body of size:" .. #complete_response_body, request_id)
		portunus:log_response_body(response_handle, request_id, complete_response_body)

		-- Log response headers, excluding credential-carrying headers
		local response_headers = {}
		for k, v in pairs(response_handle:headers() or {}) do
			if not utils.is_sensitive_header(k, sensitive_log_headers) then
				response_headers[k] = v
			end
		end
		portunus:log_response_headers(
			response_handle,
			request_id,
			utils.convert_pairs_to_table(response_handle, response_headers)
		)

		-- Log response trailers
		local response_trailers = utils.convert_pairs_to_table(response_handle, response_handle:trailers() or {})
		portunus:log_response_trailers(response_handle, request_id, response_trailers)
	end)

	if not ok then
		logging.err(response_handle, "ERROR in response logging: " .. error)
	end
end
