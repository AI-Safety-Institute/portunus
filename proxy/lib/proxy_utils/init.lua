-- Main entry point for proxy_utils library
-- This module provides utilities for the API Key Proxy

local proxy_utils = {
	_VERSION = "1.0.0",
	_DESCRIPTION = "Utility library for API Key Proxy Lua scripts",
}

-- Load submodules
proxy_utils.utils = require("proxy_utils.utils")
proxy_utils.request_signing = require("proxy_utils.request_signing")
proxy_utils.logging = require("proxy_utils.logging")
proxy_utils.portunus = require("proxy_utils.portunus")

return proxy_utils
