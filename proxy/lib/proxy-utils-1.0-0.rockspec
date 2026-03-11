rockspec_format = "3.0"
package = "proxy-utils"
version = "1.0-0"
source = {
   url = "." -- Local installation
}
description = {
   summary = "Utility library for API Key Proxy Lua scripts",
   detailed = [[
      This library contains reusable utilities for the API Key Proxy,
      including authentication helpers, request/response utilities,
      and logging functions.
   ]],
   license = "MIT"
}
dependencies = {
   "lua >= 5.1",
   "sha2",
   "base64",
   "dkjson"
}
test_dependencies = {
   "busted >= 2.0"
}
build = {
   type = "builtin",
   modules = {
      ["proxy_utils"] = "proxy_utils/init.lua",
      ["proxy_utils.utils"] = "proxy_utils/utils.lua",
      ["proxy_utils.request_signing"] = "proxy_utils/request_signing.lua",
      ["proxy_utils.logging"] = "proxy_utils/logging.lua",
      ["proxy_utils.portunus"] = "proxy_utils/portunus.lua"
   }
}
