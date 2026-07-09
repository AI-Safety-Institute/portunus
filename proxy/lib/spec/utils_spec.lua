-- Tests for proxy_utils.utils module
-- Thin wrappers around Envoy API - tested in E2E

describe("proxy_utils.utils", function()
	local utils

	before_each(function()
		package.loaded["proxy_utils.utils"] = nil
		utils = require("proxy_utils.utils")
	end)

	describe("get_full_request_body - body extraction", function()
		it("should call body:getBytes with correct range", function()
			local getBytes_spy = spy.new(function(_, offset, length)
				return "Hello, World!"
			end)
			local body_stub = {
				length = stub.new().returns(13),
				getBytes = getBytes_spy,
			}
			local handle = {
				body = stub.new().returns(body_stub),
			}

			local result = utils.get_full_request_body(handle)

			assert.spy(getBytes_spy).was.called_with(match._, 0, 13)
			assert.equals("Hello, World!", result)
		end)

		it("should return empty string for zero-length body", function()
			local getBytes_spy = spy.new()
			local body_stub = {
				length = stub.new().returns(0),
				getBytes = getBytes_spy,
			}
			local handle = {
				body = stub.new().returns(body_stub),
			}

			local result = utils.get_full_request_body(handle)

			-- getBytes should not be called for empty body
			assert.spy(getBytes_spy).was_not.called()
			assert.equals("", result)
		end)
	end)

	describe("sensitive header filtering", function()
		local default_set

		before_each(function()
			default_set = utils.sensitive_headers()
		end)

		it("should flag denylisted credential headers", function()
			assert.is_true(utils.is_sensitive_header("authorization", default_set))
			assert.is_true(utils.is_sensitive_header("proxy-authorization", default_set))
			assert.is_true(utils.is_sensitive_header("cookie", default_set))
			assert.is_true(utils.is_sensitive_header("set-cookie", default_set))
			assert.is_true(utils.is_sensitive_header("x-api-key", default_set))
			assert.is_true(utils.is_sensitive_header("api-key", default_set))
			assert.is_true(utils.is_sensitive_header("x-goog-api-key", default_set))
			assert.is_true(utils.is_sensitive_header("xi-api-key", default_set))
			assert.is_true(utils.is_sensitive_header("x-hume-api-key", default_set))
			assert.is_true(utils.is_sensitive_header("x-amz-security-token", default_set))
		end)

		it("should match case-insensitively", function()
			assert.is_true(utils.is_sensitive_header("Authorization", default_set))
			assert.is_true(utils.is_sensitive_header("X-API-KEY", default_set))
		end)

		it("should include extra headers alongside the denylist", function()
			local set = utils.sensitive_headers({ "X-Custom-Key" })
			assert.is_true(utils.is_sensitive_header("x-custom-key", set))
			assert.is_true(utils.is_sensitive_header("X-Custom-Key", set))
			assert.is_true(utils.is_sensitive_header("authorization", set))
		end)

		it("should not flag ordinary headers", function()
			local set = utils.sensitive_headers({ "x-custom-key" })
			assert.is_false(utils.is_sensitive_header("content-type", default_set))
			assert.is_false(utils.is_sensitive_header("user-agent", default_set))
			assert.is_false(utils.is_sensitive_header("content-type", set))
			assert.is_false(utils.is_sensitive_header("openai-organization", default_set))
		end)
	end)

	describe("convert_pairs_to_table - base64 encoding", function()
		it("should base64-encode all header values", function()
			local base64_spy = spy.new(function(_, data)
				return "encoded:" .. data
			end)
			local handle = {
				base64Escape = base64_spy,
			}
			local headers = {
				["content-type"] = "application/json",
				["user-agent"] = "test-client",
			}

			local result = utils.convert_pairs_to_table(handle, headers)

			-- Should have called base64Escape for each header
			assert.spy(base64_spy).was.called(2)
			assert.equals("encoded:application/json", result["content-type"])
			assert.equals("encoded:test-client", result["user-agent"])
		end)
	end)
end)
