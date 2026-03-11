-- Tests for proxy_utils.logging module
-- Pure logic tests - request ID formatting

describe("proxy_utils.logging", function()
	local logging

	before_each(function()
		package.loaded["proxy_utils.logging"] = nil
		logging = require("proxy_utils.logging")
	end)

	describe("request ID formatting", function()
		it("should format message with request_id prefix", function()
			local handle = { logInfo = spy.new() }

			logging.info(handle, "Test message", "req-123")

			assert.spy(handle.logInfo).was.called_with(match._, "[req-123] Test message")
		end)

		it("should not add prefix when request_id is nil or empty", function()
			local handle = { logInfo = spy.new() }

			logging.info(handle, "Message", nil)
			assert.spy(handle.logInfo).was.called_with(match._, "Message")

			handle = { logInfo = spy.new() }
			logging.info(handle, "Message", "")
			assert.spy(handle.logInfo).was.called_with(match._, "Message")
		end)

		it("should work across all log levels", function()
			local handle = {
				logInfo = spy.new(),
				logWarn = spy.new(),
				logErr = spy.new(),
			}

			logging.info(handle, "Info", "req-123")
			logging.warn(handle, "Warn", "req-123")
			logging.err(handle, "Error", "req-123")

			assert.spy(handle.logInfo).was.called_with(match._, "[req-123] Info")
			assert.spy(handle.logWarn).was.called_with(match._, "[req-123] Warn")
			assert.spy(handle.logErr).was.called_with(match._, "[req-123] Error")
		end)
	end)
end)
