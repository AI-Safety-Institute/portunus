"""WebSocket relay module for Portunus.

The data path lives in Envoy: a `FULL_DUPLEX_STREAMED` ext_proc filter on
WS routes streams post-upgrade frames to `extproc.ExtProcRelayServicer`,
which observes them and publishes per-message records via the existing
log queue. Auth at upgrade is handled by Envoy's Lua filter calling
`/authorise` exactly as for HTTP.
"""
