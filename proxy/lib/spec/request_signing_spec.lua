-- Tests for proxy_utils.request_signing module
-- Pure logic tests - content digest computation

describe("proxy_utils.request_signing", function()
	local request_signing
	local base64 = require("base64")
	local json = require("dkjson")

	local test_cases

	local function load_test_cases()
		if test_cases then
			return test_cases
		end

		local file = io.open("spec/anthropic_signing_test_cases.json", "r")
		if not file then
			error("Could not open test cases file")
		end
		local content = file:read("*all")
		file:close()

		test_cases = json.decode(content)
		return test_cases
	end

	before_each(function()
		package.loaded["proxy_utils.request_signing"] = nil
		request_signing = require("proxy_utils.request_signing")
	end)

	describe("compute_content_digest - cryptographic logic", function()
		it("should compute SHA-256 digest in correct format", function()
			local handle = {
				base64Escape = function(_, data)
					return base64.encode(data)
				end,
			}

			local digest = request_signing.compute_content_digest(handle, "")

			assert.is_not_nil(digest)
			assert.is_true(digest:match("^sha%-256=:.*:$") ~= nil)
		end)

		it("should match Anthropic test vector content digests", function()
			local cases = load_test_cases()

			local handle = {
				base64Escape = function(_, data)
					return base64.encode(data)
				end,
			}

			for _, test_vector in ipairs(cases.test_vectors) do
				-- Use the raw body string from test vector (byte-level digest)
				local test_body = test_vector.request.body

				local expected_digest = test_vector.expected_values.content_digest
				local digest = request_signing.compute_content_digest(handle, test_body)

				assert.equals(expected_digest, digest,
					"Content digest mismatch for " .. test_vector.algorithm)
			end
		end)

		it("should compute digest from raw bytes without normalization", function()
			local handle = {
				base64Escape = function(_, data)
					return base64.encode(data)
				end,
			}

			-- Test with two different JSON strings that have the same semantic content
			-- but different formatting - they should produce DIFFERENT digests
			local compact = '{"foo":"bar"}'
			local spaced = '{"foo": "bar"}'

			local digest_compact = request_signing.compute_content_digest(handle, compact)
			local digest_spaced = request_signing.compute_content_digest(handle, spaced)

			-- Byte-level digests should be different for different byte sequences
			assert.is_not_equals(digest_compact, digest_spaced,
				"Byte-level digests should differ for different formatting")
		end)
	end)
end)
