#!/bin/sh

# Set default values for environment variables only if they're not already set
export LISTEN_POST=${LISTEN_POST:-8888}
export RATE_LIMIT_REQUESTS_PER_INTERVAL=${RATE_LIMIT_REQUESTS_PER_INTERVAL:-1}
export RATE_LIMIT_INTERVAL_SECONDS=${RATE_LIMIT_INTERVAL_SECONDS:-1}
export RATE_LIMIT_PERCENT_ENABLED=${RATE_LIMIT_PERCENT_ENABLED:-0}
export TARGET_MAX_CONNECTIONS=${TARGET_MAX_CONNECTIONS:-10000}
export TARGET_HOST_USE_TLS=${TARGET_HOST_USE_TLS:-true}
export PORTUNUS_API_KEY=${PORTUNUS_API_KEY:-""}
export PORTUNUS_API_KEY_HEADER=${PORTUNUS_API_KEY_HEADER:-"x-api-key"}
export PORTUNUS_HEADER_PREFIX=${PORTUNUS_HEADER_PREFIX:-portunus}
export CORS_ALLOWED_ORIGINS=${CORS_ALLOWED_ORIGINS:-""}
# Loopback-only Envoy admin port, substituted into envoy.yaml; the SIGTERM
# drain orchestration at the bottom of this script drives it.
export ADMIN_PORT=${ADMIN_PORT:-9901}

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

# PORTUNUS_HOST_HTTP2_OPTIONS is intentionally absent — the Portunus cluster
# must stay HTTP/1.1 for WebSocket Upgrade support (RFC 7540 §8.1.2.2).

# WS_TARGET_HOST defaults to TARGET_HOST — in production they're the same
# (e.g., api.openai.com handles both HTTP and WS). Override in local dev
# to point WS to a separate echo server.
export WS_TARGET_HOST=${WS_TARGET_HOST:-$TARGET_HOST}

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

# PORTUNUS_TRANSPORT_SOCKET
# Force HTTP/1.1 via ALPN — WebSocket Upgrade requires HTTP/1.1 and will
# silently fail if the TLS connection negotiates HTTP/2.
if [ -z "$PORTUNUS_TRANSPORT_SOCKET" ]; then
  export PORTUNUS_TRANSPORT_SOCKET=$(yq -o json <<EOF
name: envoy.transport_sockets.tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
  sni: $PORTUNUS_HOST
  common_tls_context:
    alpn_protocols:
      - http/1.1
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

# Apply environment variable substitution to config files
envsubst < /envoy/envoy.yaml > /envoy/envoy_subst.yaml
envsubst < /envoy/lua.lua > /envoy/lua_subst.lua

# --- Graceful shutdown orchestration ---------------------------------------
#
# Envoy does NOT drain on SIGTERM: a bare SIGTERM is an immediate shutdown
# that RSTs every open connection, and --drain-time-s on its own only
# applies to hot restarts and admin-triggered drains (see
# https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/draining
# and envoyproxy/envoy#7841). That is what cuts client streams mid-response
# on every ECS scale-in or deploy. So this entrypoint owns the drain,
# mirroring Envoy Gateway's shutdown manager: on SIGTERM it
#
#   1. POSTs /healthcheck/fail — flips the drain manager so HTTP/1.1
#      connections get "Connection: close" at their next response boundary
#      and HTTP/2 connections get GOAWAY, paced across the drain window by
#      --drain-strategy gradual. (The ALB is unaffected: the Lua filter
#      answers /ping in the request phase, and by SIGTERM time ECS has
#      already deregistered this task anyway.)
#   2. POSTs /drain_listeners?graceful&skip_exit — starts the formal drain
#      sequence; skip_exit leaves the exit decision to this script.
#   3. Polls active PLAIN-HTTP downstream connections and exits via
#      /quitquitquit as soon as they hit zero, or when the
#      ${DRAIN_TIME_S}s budget expires.
#
# Scope: plain HTTP only. An in-flight streaming HTTP response (SSE, AWS
# eventstream, a slow LLM completion) keeps flowing to the client and
# completes. WebSocket (upgraded) connections are deliberately NOT held:
# they are excluded from the connection count, so they're closed when the
# drain ends — at worst exactly what a bare SIGTERM does to them today.
# WS-aware draining lands with the gRPC cutover (#19), whose entrypoint
# supersedes this one.
#
# ECS task stop is: ALB target deregistration (deregistration_delay, 10s)
# → SIGTERM → stopTimeout → SIGKILL. DRAIN_TIME_S must stay comfortably
# under stopTimeout or Envoy is SIGKILL'd mid-drain; the api-key-proxy
# proxy stack currently sets stopTimeout=30 (capping the effective drain
# at ~28s) and should be raised to 120 (the Fargate maximum) alongside
# this change. Streams longer than the budget still get cut at the
# deadline — the drain bounds the damage, it can't hold the task open
# indefinitely.
#
# The admin listener is loopback-only (${ADMIN_PORT}, default 9901):
# nothing off-task can reach it.

ADMIN="http://127.0.0.1:${ADMIN_PORT:-9901}"
DRAIN_TIME_S="${DRAIN_TIME_S:-60}"

admin_post() {
  wget -q -O /dev/null --post-data='' "${ADMIN}${1}" 2>/dev/null
}

# Active work Envoy still owes someone, summed from /stats:
#
#   * non-upgraded downstream connections (downstream_cx_active minus
#     downstream_cx_upgrades_active, so WebSocket sessions don't pin the
#     drain open — HTTP-only scope, see above), excluding http.admin.*
#     because each poll here is itself one admin connection and would
#     otherwise count its own poller and never reach zero;
#   * active upstream requests (cluster.*.upstream_rq_active) — after the
#     last client connection closes, the Lua filter's fire-and-forget
#     audit httpCalls to Portunus can still be in flight, and quitting
#     under them both loses the audit tail and trips an Envoy shutdown
#     crash (AsyncClient stream reset mid-teardown → SIGSEGV backtrace,
#     observed on 1.31 and 1.36 alike), turning a clean exit into 143.
#
# Prints 0 if the admin endpoint is unreachable, which fails towards
# "stop now" rather than hanging until SIGKILL.
active_work() {
  wget -q -O - "${ADMIN}/stats?filter=downstream_cx|upstream_rq_active" 2>/dev/null \
    | awk -F': ' '
        $1 ~ /^http\.admin\./ { next }
        $1 ~ /^http\..*\.downstream_cx_active$/ { a += $2 }
        $1 ~ /^http\..*\.downstream_cx_upgrades_active$/ { u += $2 }
        $1 ~ /^cluster\..*\.upstream_rq_active$/ { r += $2 }
        END { d = a - u; if (d < 0) d = 0; printf "%d", d + r }'
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
