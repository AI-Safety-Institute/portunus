#!/bin/sh
# Container health probe: checks the gRPC health service on every port this
# process serves, so the probe follows GRPC_ROLE / GRPC_AUDIT_PORT the same way
# portunus.grpc.server picks its listeners.
#   audit: the audit port (GRPC_AUDIT_PORT, else GRPC_PORT) — the only one bound.
#   auth:  GRPC_PORT.
#   all:   GRPC_PORT, plus GRPC_AUDIT_PORT when set. Both listeners share one
#          health servicer, so the status is the same; the second probe checks
#          that the listener Envoy's ext_proc cluster dials is accepting.
set -u
probe() {
  grpc_health_probe -addr="127.0.0.1:$1"
}
case "${GRPC_ROLE:-all}" in
  audit) probe "${GRPC_AUDIT_PORT:-$GRPC_PORT}" ;;
  auth) probe "$GRPC_PORT" ;;
  *) probe "$GRPC_PORT" && { [ -z "${GRPC_AUDIT_PORT:-}" ] || probe "$GRPC_AUDIT_PORT"; } ;;
esac
