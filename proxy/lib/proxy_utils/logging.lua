-- Logging utilities for API Key Proxy
-- Provides helpers for Envoy logging that automatically include trace IDs

local logging = {}

--- Formats a log message with optional request_id prefix
-- @param message The log message
-- @param request_id Optional request ID to prepend
-- @return Formatted message
local function format_message(message, request_id)
	if request_id and request_id ~= "" then
		return "[" .. request_id .. "] " .. message
	end
	return message
end

--- Logs an info message with optional trace ID
-- @param handle Request or response handle
-- @param message The message to log
-- @param request_id Optional request ID for tracing
function logging.info(handle, message, request_id)
	handle:logInfo(format_message(message, request_id))
end

--- Logs a warning message with optional trace ID
-- @param handle Request or response handle
-- @param message The message to log
-- @param request_id Optional request ID for tracing
function logging.warn(handle, message, request_id)
	handle:logWarn(format_message(message, request_id))
end

--- Logs an error message with optional trace ID
-- @param handle Request or response handle
-- @param message The message to log
-- @param request_id Optional request ID for tracing
function logging.err(handle, message, request_id)
	handle:logErr(format_message(message, request_id))
end

return logging
