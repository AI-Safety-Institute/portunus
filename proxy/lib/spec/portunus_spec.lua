-- Tests for proxy_utils.portunus module
-- Focused on: API contract with Portunus and pure logic

describe("proxy_utils.portunus", function()
	local portunus_module
	local portunus_client

	before_each(function()
		package.loaded["proxy_utils.portunus"] = nil
		package.loaded["proxy_utils.request_signing"] = nil
		portunus_module = require("proxy_utils.portunus")

		local config = {
			portunus_host = "portunus.test:8080",
			portunus_api_key = "test-api-key-123",
			portunus_api_key_header = "x-api-key",
			api_key_header = "authorization",
			api_key_prefix = "Bearer ",
			target_host = "api.example.com",
			signing_key_id = "",
			kms_key_arn = "",
		}
		portunus_client = portunus_module.new(config)
	end)

	-- ========================================
	-- Pure Logic Tests (no Envoy dependencies)
	-- ========================================

	describe("extract_auth_payload - string manipulation", function()
		it("should extract payload from Bearer header", function()
			local headers_stub = {
				get = stub.new().returns("Bearer my-secret-payload-123"),
			}
			local handle = {
				headers = stub.new().returns(headers_stub),
			}

			local payload, err = portunus_client:extract_auth_payload(handle)

			assert.is_nil(err)
			assert.equals("my-secret-payload-123", payload)
		end)

		it("should reject missing authorization header", function()
			local headers_stub = { get = stub.new().returns(nil) }
			local handle = { headers = stub.new().returns(headers_stub) }

			local payload, err = portunus_client:extract_auth_payload(handle)

			assert.is_nil(payload)
			assert.equals("Authorization header is required", err)
		end)

		it("should reject non-Bearer authorization", function()
			local headers_stub = { get = stub.new().returns("Basic credentials") }
			local handle = { headers = stub.new().returns(headers_stub) }

			local payload, err = portunus_client:extract_auth_payload(handle)

			assert.is_nil(payload)
			assert.equals("Invalid authorization format", err)
		end)
	end)

	describe("parse_error_response - JSON parsing", function()
		it("should parse error with message and debug_id", function()
			local body = '{"message": "Invalid credentials", "debug_id": "req-123"}'

			local error_message, trace_id = portunus_client:parse_error_response(body)

			assert.equals("Invalid credentials", error_message)
			assert.equals("req-123", trace_id)
		end)

		it("should handle missing fields with defaults", function()
			local body = '{"message": "Error"}'
			local error_message, trace_id = portunus_client:parse_error_response(body)
			assert.equals("Error", error_message)
			assert.equals("unknown", trace_id)

			body = '{"debug_id": "req-456"}'
			error_message, trace_id = portunus_client:parse_error_response(body)
			assert.equals("Authorization failed", error_message)
			assert.equals("req-456", trace_id)

			body = "{}"
			error_message, trace_id = portunus_client:parse_error_response(body)
			assert.equals("Authorization failed", error_message)
			assert.equals("unknown", trace_id)
		end)

		it("should handle invalid JSON gracefully", function()
			local error_message, trace_id = portunus_client:parse_error_response("not json")
			assert.equals("not json", error_message)
			assert.equals("unknown", trace_id)

			error_message, trace_id = portunus_client:parse_error_response("")
			assert.equals("Authorization failed", error_message)
			assert.equals("unknown", trace_id)

			error_message, trace_id = portunus_client:parse_error_response(nil)
			assert.equals("Authorization failed", error_message)
			assert.equals("unknown", trace_id)
		end)
	end)

	describe("parse_authorization_response - JSON parsing", function()
		it("should parse valid response with all fields", function()
			local body =
				'{"api_key": "sk-test-123", "request_id": "req-abc", "signature": "sig-xyz", "signature_input": "sig-input-def"}'

			local data, err = portunus_client:parse_authorization_response(body)

			assert.is_nil(err)
			assert.is_not_nil(data)
			assert.equals("sk-test-123", data.api_key)
			assert.equals("req-abc", data.request_id)
			assert.equals("sig-xyz", data.signature)
			assert.equals("sig-input-def", data.signature_input)
		end)

		it("should parse response with required fields only", function()
			local body = '{"api_key": "sk-test-456", "request_id": "req-def"}'

			local data, err = portunus_client:parse_authorization_response(body)

			assert.is_nil(err)
			assert.equals("sk-test-456", data.api_key)
			assert.equals("req-def", data.request_id)
			assert.is_nil(data.signature)
		end)

		it("should return error for invalid responses", function()
			local data, err = portunus_client:parse_authorization_response("not json")
			assert.is_nil(data)
			assert.equals("Failed to parse response from authorization service", err)

			data, err = portunus_client:parse_authorization_response('{"request_id": "req-xyz"}')
			assert.is_nil(data)
			assert.equals("Invalid response from auth service", err)

			data, err = portunus_client:parse_authorization_response('{"api_key": "sk-test-789"}')
			assert.is_nil(data)
			assert.equals("Invalid response from auth service", err)
		end)
	end)

	-- ========================================
	-- API Contract Tests (verify Portunus API structure)
	-- ========================================

	describe("authorise - Portunus API contract", function()
		it("should structure /authorise request correctly", function()
			local headers_stub = {
				get = function(_, key)
					local headers_map = {
						["content-type"] = "application/json",
						[":method"] = "POST",
						[":scheme"] = "https",
						[":authority"] = "api.example.com",
						[":path"] = "/v1/messages",
					}
					return headers_map[key]
				end,
			}
			local handle = {
				headers = stub.new().returns(headers_stub),
				httpCall = spy.new(),
			}

			portunus_client:authorise(handle, "test-payload", "sha-256=:abc:")

			-- Verify we made exactly one call
			assert.spy(handle.httpCall).was.called(1)

			-- Extract the call arguments
			local call_args = handle.httpCall.calls[1].vals
			local host = call_args[2]
			local headers = call_args[3]
			local body = call_args[4]
			local timeout = call_args[5]
			local async = call_args[6]

			-- Verify API contract
			assert.equals("portunus.test:8080", host)
			assert.equals("POST", headers[":method"])
			assert.equals("/authorise", headers[":path"])
			assert.equals("portunus.test:8080", headers[":authority"])
			assert.equals("application/json", headers["content-type"])
			assert.equals("test-api-key-123", headers["x-api-key"])
			assert.equals(10000, timeout)
			assert.is_false(async) -- authorise is synchronous

			-- Verify body structure
			local json = require("dkjson")
			local decoded = json.decode(body)
			assert.equals("test-payload", decoded.payload)
			assert.equals("api.example.com", decoded.target_host)
			-- signable_request is always included (backend checks auth secret for signing config)
			assert.is_not_nil(decoded.signable_request)
			assert.equals("anthropic", decoded.signable_request.type)
			assert.equals("sha-256=:abc:", decoded.signable_request.content_digest)
			assert.equals("application/json", decoded.signable_request.content_type)
			assert.equals("POST", decoded.signable_request.method)
			assert.equals("https://api.example.com/v1/messages", decoded.signable_request.url)
		end)
	end)

	describe("logging endpoints - Portunus API contract", function()
		it("should structure log request body endpoint correctly", function()
			local handle = { httpCall = spy.new() }

			portunus_client:log_request_body(handle, "req-123", "test body")

			local call_args = handle.httpCall.calls[1].vals
			local headers = call_args[3]
			local body = call_args[4]
			local async = call_args[6]

			-- Verify endpoint structure
			assert.equals("POST", headers[":method"])
			assert.equals("/log/req-123/request/body", headers[":path"])
			assert.equals("application/octet-stream", headers["content-type"])
			assert.equals("test body", body)
			assert.is_true(async) -- logging is async
		end)

		it("should structure log request headers endpoint correctly", function()
			local handle = { httpCall = spy.new() }
			local test_headers = {
				["user-agent"] = "test-client",
				["content-type"] = "application/json",
			}

			portunus_client:log_request_headers(handle, "req-456", test_headers)

			local call_args = handle.httpCall.calls[1].vals
			local headers = call_args[3]
			local body = call_args[4]

			assert.equals("/log/req-456/request/headers", headers[":path"])
			assert.equals("application/json", headers["content-type"])

			-- Verify body structure and content
			local json = require("dkjson")
			local decoded = json.decode(body)
			assert.is_not_nil(decoded.timestamp)
			assert.is_not_nil(decoded.headers)
			-- Verify the actual headers were included (base64-encoded)
			assert.is_not_nil(decoded.headers["user-agent"])
			assert.is_not_nil(decoded.headers["content-type"])
		end)

	end)

	-- ========================================
	-- Error Handling Tests
	-- ========================================

	describe("error handling", function()
		it("should not throw errors if httpCall fails for async log methods", function()
			local handle = {
				httpCall = function()
					error("Network failure")
				end,
			}

			-- All async log methods should handle errors gracefully via pcall
			assert.has_no_errors(function()
				portunus_client:log_request_body(handle, "req-1", "body")
			end)
			assert.has_no_errors(function()
				portunus_client:log_request_headers(handle, "req-2", {})
			end)
			assert.has_no_errors(function()
				portunus_client:log_response_body(handle, "req-3", "body")
			end)
		end)

		it("should propagate errors from synchronous authorise method", function()
			local handle = {
				httpCall = function()
					error("Auth service unavailable")
				end,
			}

			-- authorise should NOT catch errors (unlike log methods)
			assert.has_error(function()
				portunus_client:authorise(handle, "test", "sha-256=:digest:")
			end)
		end)
	end)
end)
