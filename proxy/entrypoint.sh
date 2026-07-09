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
# ECS task stop is: ALB target deregistration → wait deregistration_delay
# → SIGTERM → stopTimeout → SIGKILL. Two platform values bracket this
# drain, and BOTH must be sized for it or it silently does nothing:
#
#   * deregistration_delay (ALB target group) — the ALB severs remaining
#     in-flight connections to the target when the delay elapses, and ECS
#     only sends SIGTERM after it. platform-lib-cdk currently hardcodes
#     10s ("faster deregistration"), so in prod every stream older than
#     ~10s is cut by the ALB BEFORE this drain even starts; the drain
#     then sees near-zero active work and exits promptly, looking clean
#     while customers were cut upstream of Envoy. The delay must be
#     raised to ≥ DRAIN_TIME_S for the proxy target groups (specced in
#     the akp/platform-lib-cdk change set; see
#     docs/cutover-landing-order.md). docker-compose drain tests cannot
#     see this dependency — there is no ALB in compose.
#   * stopTimeout (ECS container) — DRAIN_TIME_S must stay comfortably
#     under it or Envoy is SIGKILL'd (137) mid-drain. The blue fleet
#     (akp #136) sets 120s (the Fargate max) against the default
#     DRAIN_TIME_S=60. NOTE the legacy fleet's stopTimeout is still 30s:
#     shipping this entrypoint there (#35) without raising it SIGKILLs
#     the drain at ~28s — the stopTimeout bump must travel with the
#     legacy-ref bump.
#
# Streams longer than the budget still get cut at the deadline — the
# drain bounds the damage, it can't hold the task open indefinitely.
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
#   * downstream connections (WebSocket upgrades included — an upgraded
#     connection still belongs to the HCM), excluding http.admin.*
#     because each poll here is itself one admin connection and would
#     otherwise count its own poller and never reach zero;
#   * active upstream requests (cluster.*.upstream_rq_active) — the
#     ext_authz/ext_proc gRPC streams and any trailing audit work can
#     outlive the last downstream connection, and quitting under an
#     in-flight AsyncClient stream trips an Envoy shutdown SIGSEGV
#     (AsyncClient teardown, observed on the Lua/REST branch on 1.31 and
#     1.36 alike) and loses the audit tail.
#
# Prints 0 if the admin endpoint is unreachable, which fails towards
# "stop now" rather than hanging until SIGKILL.
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

# Envoy version tripwire. #34/#35 exist because 1.31 SIGSEGVs on shutdown
# under an in-flight AsyncClient stream (drain linger + lost audit tail),
# and 1.31 boots this config cleanly — so a careless resolution of the
# #31↔#34 Dockerfile FROM-line conflict would ship the bad version with
# every health check green. The build asserts this too (proxy/Dockerfile);
# this runtime copy catches an image swapped at the task-definition level.
EXPECTED_ENVOY_MINOR="${EXPECTED_ENVOY_MINOR:-1.36}"
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
