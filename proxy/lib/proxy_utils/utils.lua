-- General utility functions for API Key Proxy

local utils = {}

-- Headers that must never be logged, regardless of which provider the proxy
-- is configured for. Clients sometimes send credentials in a different header
-- than the one this proxy replaces (config.api_key_header), e.g. an
-- `authorization` bearer token through a proxy configured for `x-api-key`.
-- Those would otherwise be logged verbatim to the audit trail.
local SENSITIVE_HEADERS = {
	["authorization"] = true,
	["proxy-authorization"] = true,
	["cookie"] = true,
	["set-cookie"] = true,
	["x-api-key"] = true, -- Anthropic
	["api-key"] = true, -- Azure OpenAI
	["x-goog-api-key"] = true, -- Google
	["xi-api-key"] = true, -- ElevenLabs
	["x-hume-api-key"] = true, -- Hume
	["x-amz-security-token"] = true, -- AWS session token (SigV4 requests)
}

--- Builds the set of headers to exclude from logging
-- @param extra_headers Optional array of additional header names to exclude
--        (e.g. the proxy's configured api_key_header)
-- @return Set of lowercase header names, keyed by name
function utils.sensitive_headers(extra_headers)
	local headers = {}
	for name in pairs(SENSITIVE_HEADERS) do
		headers[name] = true
	end
	for _, name in ipairs(extra_headers or {}) do
		headers[string.lower(name)] = true
	end
	return headers
end

--- Checks whether a header must be excluded from logging
-- @param name Header name (matched case-insensitively)
-- @param sensitive_headers Set built by utils.sensitive_headers()
-- @return true if the header carries credentials and must not be logged
function utils.is_sensitive_header(name, sensitive_headers)
	return sensitive_headers[string.lower(name)] == true
end

--- Converts a Lua table of key-value pairs to a table with base64-encoded values
-- @param handle The Envoy request or response handle
-- @param headers The headers table to convert
-- @return result A table with base64-encoded values
function utils.convert_pairs_to_table(handle, headers)
	local result = {}
	for key, value in pairs(headers) do
		result[key] = handle:base64Escape(value)
	end
	setmetatable(result, { __jsontype = "object" }) -- always serialise as {}
	return result
end

--- Gets the full request body from the request handle
-- @param request_handle The Envoy request handle
-- @return full_request_body The complete request body as a string
function utils.get_full_request_body(request_handle)
	local full_request_body = ""
	local body = request_handle:body()

	if body and body:length() > 0 then
		full_request_body = body:getBytes(0, body:length())
	end

	return full_request_body
end

return utils
