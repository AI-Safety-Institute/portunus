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

# --- Graceful shutdown ------------------------------------------------------
# Envoy doesn't drain on SIGTERM (it exits and RSTs open connections, cutting
# client streams on every ECS scale-in/deploy); --drain-time-s only paces an
# already-started drain, so we trigger it via the admin API — /healthcheck/fail,
# /drain_listeners, then /quitquitquit once work drains or DRAIN_TIME_S expires
# (mirrors Envoy Gateway's shutdown manager; envoyproxy/envoy#7841).
# HTTP-only: in-flight streams finish; WebSockets close at drain end (#19
# supersedes). DRAIN_TIME_S must stay under ECS stopTimeout (30s today, raise
# to 120s). Admin is loopback-only.

ADMIN="http://127.0.0.1:${ADMIN_PORT:-9901}"
DRAIN_TIME_S="${DRAIN_TIME_S:-60}"

admin_post() {
  wget -q -O /dev/null --post-data='' "${ADMIN}${1}" 2>/dev/null
}

# Work Envoy still owes, from /stats: non-upgraded downstream connections
# (exclude WS so they don't pin the drain; exclude http.admin.* self-count)
# plus upstream_rq_active — the Lua fire-and-forget audit httpCalls, which must
# finish before we quit (quitting under them loses audit + can crash Envoy on
# teardown). Prints 0 if admin is unreachable (fail toward stop, not hang).
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

# wait returns >128 on trap interrupt; loop until Envoy actually exits so its
# real exit code (0 after /quitquitquit) becomes the container's.
EXIT_CODE=0
while :; do
  wait "$ENVOY_PID"
  EXIT_CODE=$?
  kill -0 "$ENVOY_PID" 2>/dev/null || break
done
exit "$EXIT_CODE"
