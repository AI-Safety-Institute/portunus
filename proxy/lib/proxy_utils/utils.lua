-- General utility functions for API Key Proxy

local utils = {}

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

--- Parses a comma-separated list of header names into a lookup set
-- Names are trimmed and lowercased; empty entries are skipped.
-- @param list Comma-separated header names (nil is treated as empty)
-- @return set Table mapping each lowercased header name to true
function utils.parse_header_set(list)
	local set = {}
	for name in (list or ""):gmatch("[^,]+") do
		local trimmed = name:match("^%s*(.-)%s*$"):lower()
		if trimmed ~= "" then
			set[trimmed] = true
		end
	end
	return set
end

return utils
