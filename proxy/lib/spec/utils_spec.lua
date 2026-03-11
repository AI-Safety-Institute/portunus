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
