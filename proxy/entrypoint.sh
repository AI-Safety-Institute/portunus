#!/bin/sh

# WS upstream defaults to the HTTP target host. Done here because envsubst
# can't do indirect defaults (${X:-${Y}}).
export WS_TARGET_HOST=${WS_TARGET_HOST:-${TARGET_HOST}}
export WS_TARGET_PORT=${WS_TARGET_PORT:-${TARGET_PORT}}

# Pre-shared key proving the proxy's identity to Portunus's gRPC server.
# Substituted into envoy.yaml as the x-portunus-proxy-key initial_metadata.
export PORTUNUS_API_KEY=${PORTUNUS_API_KEY:-""}

# TARGET_HOST_HTTP2_OPTIONS
if [ -z "$TARGET_HOST_HTTP2_OPTIONS" ]; then
  export TARGET_HOST_HTTP2_OPTIONS=$(yq -o json <<EOF
connection_keepalive:
  interval: "60s"
  timeout: "10s"
  connection_idle_interval: "10s"
EOF
  )
fi

# TARGET_HOST_TRANSPORT_SOCKET
if [ -z "$TARGET_HOST_TRANSPORT_SOCKET" ]; then
  export TARGET_HOST_TRANSPORT_SOCKET=$(yq -o json <<EOF
name: envoy.transport_sockets.tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
  sni: $TARGET_HOST
  common_tls_context:
    validation_context:
      trusted_ca:
        filename: /etc/ssl/certs/ca-certificates.crt
EOF
  )
fi

# WS_TARGET_HOST_TRANSPORT_SOCKET — TLS by default (HTTPS upstream in prod);
# tests override to "null" because ws-echo is plaintext.
if [ -z "$WS_TARGET_HOST_TRANSPORT_SOCKET" ]; then
  export WS_TARGET_HOST_TRANSPORT_SOCKET=$(yq -o json <<EOF
name: envoy.transport_sockets.tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
  sni: $WS_TARGET_HOST
  common_tls_context:
    validation_context:
      trusted_ca:
        filename: /etc/ssl/certs/ca-certificates.crt
EOF
  )
fi

# DOWNSTREAM_TLS_TRANSPORT_SOCKET
if [ -z "$DOWNSTREAM_TLS_TRANSPORT_SOCKET" ]; then
  export DOWNSTREAM_TLS_TRANSPORT_SOCKET=$(yq -o json <<EOF
name: envoy.transport_sockets.tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
  common_tls_context:
    alpn_protocols: h2
    tls_certificates:
      - certificate_chain:
          filename: /envoy/cert.crt
        private_key:
          filename: /envoy/cert.key
EOF
  )
fi

# Apply environment variable substitution to the Envoy config.
envsubst < /envoy/envoy.yaml > /envoy/envoy_subst.yaml

# --- Graceful shutdown orchestration ---------------------------------------
#
# Envoy does NOT drain on SIGTERM: a bare SIGTERM RSTs every open connection,
# and --drain-time-s alone only applies to hot restarts and admin-triggered
# drains (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/draining).
# So this entrypoint owns the drain: on SIGTERM it
#
#   1. POSTs /healthcheck/fail — HTTP/1.1 gets "Connection: close" at the next
#      response boundary, HTTP/2 gets GOAWAY, paced by --drain-strategy gradual.
#   2. POSTs /drain_listeners?graceful&skip_exit — skip_exit leaves the exit
#      decision to this script.
#   3. Polls active work and /quitquitquit's once it hits zero or the
#      ${DRAIN_TIME_S}s budget expires.
#
# In-flight HTTP streams (SSE, slow completions) complete; WS sessions stay
# open until the client closes or the budget expires (then TCP FIN → 1006).
#
# Two platform values must bracket this drain or it silently does nothing:
#   * ALB target-group deregistration_delay must be ≥ DRAIN_TIME_S — the ALB
#     severs in-flight connections when it elapses and ECS only SIGTERMs after,
#     so a shorter delay cuts customers before the drain even starts (and it
#     then sees near-zero work and exits looking clean).
#   * ECS container stopTimeout must stay comfortably above DRAIN_TIME_S, else
#     Envoy is SIGKILL'd (137) mid-drain.
# Streams longer than the budget are still cut at the deadline; the drain
# bounds the damage, it can't hold the task open indefinitely.

ADMIN="http://127.0.0.1:${ADMIN_PORT:-9901}"
DRAIN_TIME_S="${DRAIN_TIME_S:-60}"

admin_post() {
  wget -q -O /dev/null --post-data='' "${ADMIN}${1}" 2>/dev/null
}

# Active work Envoy still owes someone, summed from /stats:
#   * downstream_cx_active (WS upgrades included), excluding http.admin.*
#     because each poll is itself an admin connection and would count its own
#     poller, never reaching zero;
#   * upstream_rq_active — ext_authz/ext_proc gRPC streams and trailing audit
#     work can outlive the last downstream connection, and quitting under an
#     in-flight AsyncClient stream trips an Envoy shutdown SIGSEGV and loses
#     the audit tail.
# Prints 0 if the admin endpoint is unreachable, failing toward "stop now"
# rather than hanging until SIGKILL.
active_work() {
  wget -q -O - "${ADMIN}/stats?filter=downstream_cx_active|upstream_rq_active" 2>/dev/null \
    | awk -F': ' '
        $1 ~ /^http\.admin\./ { next }
        $1 ~ /^cluster\.portunus_health_cluster\./ { next }
        $1 ~ /^http\..*\.downstream_cx_active$/ { s += $2 }
        $1 ~ /^cluster\..*\.upstream_rq_active$/ { s += $2 }
        END { printf "%d", s+0 }'
}

drain_and_quit() {
  trap '' TERM INT # one drain; from here ECS only escalates to SIGKILL
  echo "[entrypoint] SIGTERM: draining for up to ${DRAIN_TIME_S}s" >&2
  admin_post "/healthcheck/fail"
  admin_post "/drain_listeners?graceful&skip_exit"
  deadline=$(($(date +%s) + DRAIN_TIME_S))
  cx=$(active_work)
  while [ "$(date +%s)" -lt "$deadline" ] && [ "${cx:-0}" -gt 0 ]; do
    sleep 1
    cx=$(active_work)
  done
  echo "[entrypoint] drain done (active work: ${cx:-0}); stopping Envoy" >&2
  admin_post "/quitquitquit" || kill -TERM "$ENVOY_PID" 2>/dev/null
}

# Envoy version tripwire: 1.31 boots this config cleanly but SIGSEGVs on
# shutdown under an in-flight AsyncClient stream (lost audit tail), so the
# version must be pinned. proxy/Dockerfile asserts this at build; this
# runtime copy catches an image swapped at the task-definition level.
EXPECTED_ENVOY_MINOR="${EXPECTED_ENVOY_MINOR:-1.38}"
if ! envoy --version | grep -q "/${EXPECTED_ENVOY_MINOR}\."; then
  echo "[entrypoint] FATAL: running Envoy is not v${EXPECTED_ENVOY_MINOR}.x:" >&2
  envoy --version >&2
  exit 1
fi

envoy -c /envoy/envoy_subst.yaml \
  --log-level "${ENVOY_LOG_LEVEL:-info}" \
  --drain-time-s "$DRAIN_TIME_S" \
  --drain-strategy gradual &
ENVOY_PID=$!
trap drain_and_quit TERM INT

# wait returns >128 when interrupted by the trap; loop until Envoy actually
# exits so its real exit code (0 after /quitquitquit) becomes the container's.
EXIT_CODE=0
while :; do
  wait "$ENVOY_PID"
  EXIT_CODE=$?
  kill -0 "$ENVOY_PID" 2>/dev/null || break
done
exit "$EXIT_CODE"
