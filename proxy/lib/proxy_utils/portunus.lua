-- Portunus API client for API Key Proxy
-- Handles all HTTP communication with the Portunus service
local dkjson = require("dkjson")
local request_signing = require("proxy_utils.request_signing")

local portunus = {}
local portunus_client = {}
portunus_client.__index = portunus_client

--- Creates a new Portunus client instance
-- @param config Configuration table
-- @return A new Portunus client instance
function portunus.new(config)
	local instance = {
		-- Portunus connection config
		host = config.portunus_host,
		api_key = config.portunus_api_key,
		api_key_header = config.portunus_api_key_header,
		-- Request auth config
		request_api_key_header = config.api_key_header,
		request_api_key_prefix = config.api_key_prefix,
		target_host = config.target_host,
		-- Request signing config
		signing_key_id = config.signing_key_id,
		kms_key_arn = config.kms_key_arn,
		-- Header prefix for proxy-specific response headers
		header_prefix = config.header_prefix,
	}
	setmetatable(instance, portunus_client)
	return instance
end

--- Sends an error response to the client
-- @param request_handle The Envoy request handle
-- @param status_code HTTP status code to return
-- @param message Error message to include in response
-- @param request_id Request ID for tracing
function portunus_client:send_error_response(request_handle, status_code, message, request_id)
	request_handle:respond(
		{
			[":status"] = tostring(status_code),
			["content-type"] = "application/json; charset=utf-8",
			["x-" .. self.header_prefix .. "-error"] = "true",
			["X-Amzn-Trace-Id"] = request_id,
		},
		dkjson.encode({
			error = {
				message = message,
				x_amzn_trace_id = request_id,
			},
		})
	)
end

--- Extracts the authorization payload from the request headers
-- @param request_handle The Envoy request handle
-- @return payload, error The extracted payload or nil and an error message
function portunus_client:extract_auth_payload(request_handle)
	local auth_header = request_handle:headers():get(self.request_api_key_header)

	if not auth_header then
		return nil, "Authorization header is required"
	end

	if not auth_header:find("^" .. self.request_api_key_prefix) then
		return nil, "Invalid authorization format"
	end

	-- Remove the prefix (e.g., "Bearer ")
	return auth_header:sub(#self.request_api_key_prefix + 1), nil
end

--- Makes a synchronous call to Portunus /authorise endpoint
-- @param handle Request handle
-- @param auth_payload The authorization payload extracted from the request
-- @param content_digest The content digest for request signing
-- @return headers, body Response headers and body from Portunus
function portunus_client:authorise(handle, auth_payload, content_digest)
	-- Build the request body
	local request_body = {
		payload = auth_payload,
		target_host = self.target_host,
		-- Request signing inputs will be ignored by the authorise endpoint
		-- unless the api key secret includes a signing key to use.
		signable_request = {
			type = "anthropic",
			content_digest = content_digest,
			content_type = handle:headers():get("content-type") or "",
			method = handle:headers():get(":method"),
			url = handle:headers():get(":scheme")
				.. "://"
				.. handle:headers():get(":authority")
				.. handle:headers():get(":path"),
		}
	}

	return handle:httpCall(
		self.host,
		{
			[":method"] = "POST",
			[":path"] = "/authorise",
			[":authority"] = self.host,
			["content-type"] = "application/json",
			[self.api_key_header] = self.api_key,
		},
		dkjson.encode(request_body),
		10000,
		false -- synchronous
	)
end

--- Logs request body to Portunus
-- @param handle Request handle
-- @param request_id Request ID
-- @param body Request body (raw bytes)
function portunus_client:log_request_body(handle, request_id, body)
	pcall(function()
		handle:httpCall(
			self.host,
			{
				[":method"] = "POST",
				[":path"] = "/log/" .. request_id .. "/request/body",
				[":authority"] = self.host,
				["content-type"] = "application/octet-stream",
				[self.api_key_header] = self.api_key,
			},
			body,
			10000,
			true -- async
		)
	end)
end

--- Logs request headers to Portunus
-- @param handle Request handle
-- @param request_id Request ID
-- @param headers Headers table (already base64-encoded)
function portunus_client:log_request_headers(handle, request_id, headers)
	local payload = {
		timestamp = os.time(),
		headers = headers,
	}
	pcall(function()
		handle:httpCall(
			self.host,
			{
				[":method"] = "POST",
				[":path"] = "/log/" .. request_id .. "/request/headers",
				[":authority"] = self.host,
				["content-type"] = "application/json",
				[self.api_key_header] = self.api_key,
			},
			dkjson.encode(payload),
			10000,
			true -- async
		)
	end)
end

--- Logs request trailers to Portunus
-- @param handle Request handle
-- @param request_id Request ID
-- @param trailers Trailers table (already base64-encoded)
function portunus_client:log_request_trailers(handle, request_id, trailers)
	local payload = {
		timestamp = os.time(),
		trailers = trailers,
	}
	pcall(function()
		handle:httpCall(
			self.host,
			{
				[":method"] = "POST",
				[":path"] = "/log/" .. request_id .. "/request/trailers",
				[":authority"] = self.host,
				["content-type"] = "application/json",
				[self.api_key_header] = self.api_key,
			},
			dkjson.encode(payload),
			10000,
			true -- async
		)
	end)
end

--- Logs response body to Portunus
-- @param handle Response handle
-- @param request_id Request ID
-- @param body Response body (raw bytes)
function portunus_client:log_response_body(handle, request_id, body)
	pcall(function()
		handle:httpCall(
			self.host,
			{
				[":method"] = "POST",
				[":path"] = "/log/" .. request_id .. "/response/body",
				[":authority"] = self.host,
				["content-type"] = "application/octet-stream",
				[self.api_key_header] = self.api_key,
			},
			body,
			10000,
			true -- async
		)
	end)
end

--- Logs response headers to Portunus
-- @param handle Response handle
-- @param request_id Request ID
-- @param headers Headers table (already base64-encoded)
function portunus_client:log_response_headers(handle, request_id, headers)
	local payload = {
		timestamp = os.time(),
		headers = headers,
	}
	pcall(function()
		handle:httpCall(
			self.host,
			{
				[":method"] = "POST",
				[":path"] = "/log/" .. request_id .. "/response/headers",
				[":authority"] = self.host,
				["content-type"] = "application/json",
				[self.api_key_header] = self.api_key,
			},
			dkjson.encode(payload),
			10000,
			true -- async
		)
	end)
end

--- Logs response trailers to Portunus
-- @param handle Response handle
-- @param request_id Request ID
-- @param trailers Trailers table (already base64-encoded)
function portunus_client:log_response_trailers(handle, request_id, trailers)
	local payload = {
		timestamp = os.time(),
		trailers = trailers,
	}
	pcall(function()
		handle:httpCall(
			self.host,
			{
				[":method"] = "POST",
				[":path"] = "/log/" .. request_id .. "/response/trailers",
				[":authority"] = self.host,
				["content-type"] = "application/json",
				[self.api_key_header] = self.api_key,
			},
			dkjson.encode(payload),
			10000,
			true -- async
		)
	end)
end

--- Parses an ErrorResponse from Portunus service
-- ErrorResponse format:
-- {
--   "message": "Detailed error message",
--   "debug_id": "Trace or debug ID"
-- }
-- @param body Raw response body string
-- @return error_message, trace_id Extracted error message and trace ID, or defaults if parsing fails
function portunus_client:parse_error_response(body)
	local error_message = "Authorization failed"
	local request_id = "unknown"

	if body and body ~= "" then
		local error_data, _, decode_err = dkjson.decode(body)
		if not decode_err and error_data then
			if error_data.message then
				error_message = error_data.message
			end
			if error_data.debug_id then
				request_id = error_data.debug_id
			end
		else
			-- If we can't decode, use raw body
			error_message = body
		end
	end

	return error_message, request_id
end

--- Parses an AuthorizationResponse from Portunus service
-- AuthorizationResponse format:
-- {
--   "api_key": "The real API key retrieved from Secrets Manager",
--   "request_id": "Trace or request ID for logging correlation",
--   "signature": "Optional signature header value",
--   "signature_input": "Optional signature-input header value"
-- }
-- @param body Raw response body string
-- @return data, error Returns parsed data table or nil with an error message
function portunus_client:parse_authorization_response(body)
	local data, _, err = dkjson.decode(body)
	if err then
		return nil, "Failed to parse response from authorization service"
	end

	if not data or not data.api_key or not data.request_id then
		return nil, "Invalid response from auth service"
	end

	return data, nil
end

return portunus
