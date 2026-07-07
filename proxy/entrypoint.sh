#!/bin/sh

# WS-only upstream. In prod we typically point WS and HTTP at the same
# provider host (OpenAI Realtime, Anthropic streaming etc. serve both
# from one endpoint); the env var split exists so docker-compose tests
# can route plain HTTP at http-bun while WS goes to a dedicated echo
# server. envsubst can't do indirect defaults (${X:-${Y}}), so this
# stays in entrypoint.sh.
export WS_TARGET_HOST=${WS_TARGET_HOST:-${TARGET_HOST}}
export WS_TARGET_PORT=${WS_TARGET_PORT:-${TARGET_PORT}}

# Pre-shared key proving the proxy's identity to Portunus's gRPC server.
# Injected by the api-key-proxy task definition from Secrets Manager;
# substituted into the ext_authz / ext_proc filter configs in envoy.yaml
# as the static `x-portunus-proxy-key` gRPC initial_metadata value.
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

# WS_TARGET_HOST_TRANSPORT_SOCKET — defaults to the HTTP cluster's
# transport socket so prod (HTTPS upstream) Just Works. Tests override
# to "null" because ws-echo is plaintext over docker-compose network.
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
# Envoy does NOT drain on SIGTERM: a bare SIGTERM is an immediate shutdown
# that RSTs every open connection, and --drain-time-s on its own only
# applies to hot restarts and admin-triggered drains (see
# https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/draining
# and envoyproxy/envoy#7841). So this entrypoint owns the drain, mirroring
# Envoy Gateway's shutdown manager: on SIGTERM it
#
#   1. POSTs /healthcheck/fail — flips the drain manager so HTTP/1.1
#      connections get "Connection: close" at their next response boundary
#      and HTTP/2 connections get GOAWAY, paced across the drain window by
#      --drain-strategy gradual. (The ALB is unaffected: it health-checks
#      the /ping direct_response route, and by SIGTERM time ECS has already
#      deregistered this task anyway.)
#   2. POSTs /drain_listeners?graceful&skip_exit — starts the formal drain
#      sequence; skip_exit leaves the exit decision to this script.
#   3. Polls active downstream connections and exits via /quitquitquit as
#      soon as they hit zero, or when the ${DRAIN_TIME_S}s budget expires.
#
# What that means per protocol: an in-flight streaming HTTP response (SSE,
# AWS eventstream, a slow LLM completion) keeps flowing to the client and
# completes; established WebSocket sessions stay open until the client
# closes or the budget expires (then TCP FIN → clients see 1006 Abnormal
# Closure and reconnect via SDK — a clean 1001 close frame would need a
# WASM filter; tracked as follow-up).
#
# ECS task stop is: ALB target deregistration (deregistration_delay, 10s)
# → SIGTERM → stopTimeout → SIGKILL. DRAIN_TIME_S must stay comfortably
# under stopTimeout (120s in the api-key-proxy CDK proxy stack, the
# Fargate maximum) or Envoy is SIGKILL'd mid-drain. Streams longer than
# the budget still get cut at the deadline — the drain bounds the damage,
# it can't hold the task open indefinitely.
#
# The admin listener is loopback-only (${ADMIN_PORT}, default 9901):
# nothing off-task can reach it.

ADMIN="http://127.0.0.1:${ADMIN_PORT:-9901}"
DRAIN_TIME_S="${DRAIN_TIME_S:-60}"

admin_post() {
  wget -q -O /dev/null --post-data='' "${ADMIN}${1}" 2>/dev/null
}

# Sum of active downstream connections across HTTP connection managers
# (WebSocket upgrades included — an upgraded connection still belongs to
# the HCM). The admin interface's own stats live under http.admin.* and
# each poll here is itself one admin connection, so that scope must be
# excluded or the drain counts its own poller and never reaches zero.
# Prints 0 if the admin endpoint is unreachable, which fails towards
# "stop now" rather than hanging until SIGKILL.
active_cx() {
  wget -q -O - "${ADMIN}/stats?filter=downstream_cx_active" 2>/dev/null \
    | awk -F': ' '/^http\.admin\./ { next } /^http\..*\.downstream_cx_active/ { s += $2 } END { printf "%d", s+0 }'
}

drain_and_quit() {
  trap '' TERM INT # one drain; from here ECS only escalates to SIGKILL
  echo "[entrypoint] SIGTERM: draining for up to ${DRAIN_TIME_S}s" >&2
  admin_post "/healthcheck/fail"
  admin_post "/drain_listeners?graceful&skip_exit"
  deadline=$(($(date +%s) + DRAIN_TIME_S))
  cx=$(active_cx)
  while [ "$(date +%s)" -lt "$deadline" ] && [ "${cx:-0}" -gt 0 ]; do
    sleep 1
    cx=$(active_cx)
  done
  echo "[entrypoint] drain done (active connections: ${cx:-0}); stopping Envoy" >&2
  admin_post "/quitquitquit" || kill -TERM "$ENVOY_PID" 2>/dev/null
}

envoy -c /envoy/envoy_subst.yaml \
  --log-level "${ENVOY_LOG_LEVEL:-info}" \
  --drain-time-s "$DRAIN_TIME_S" \
  --drain-strategy gradual &
ENVOY_PID=$!
trap drain_and_quit TERM INT

# wait returns >128 when interrupted by the trap; loop until Envoy has
# actually exited so its real exit code (0 after /quitquitquit) becomes
# the container's.
EXIT_CODE=0
while :; do
  wait "$ENVOY_PID"
  EXIT_CODE=$?
  kill -0 "$ENVOY_PID" 2>/dev/null || break
done
exit "$EXIT_CODE"
