-- Request signing utilities for API Key Proxy
local sha2 = require("sha2")

local request_signing = {}

--- Computes the content digest for request signing
-- SHA-256 digest of the raw request body bytes.
-- @param request_handle The Envoy request handle
-- @param full_request_body The complete request body
-- @return content_digest The computed digest in the format "sha-256=:base64:"
function request_signing.compute_content_digest(request_handle, full_request_body)
	local body_hash = sha2.sha256(full_request_body or "")
	local content_digest = "sha-256=:" .. request_handle:base64Escape(body_hash) .. ":"
	return content_digest
end

return request_signing
