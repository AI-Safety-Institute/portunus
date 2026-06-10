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

# Start Envoy with the substituted config.
#
# --drain-time-s 60: on SIGTERM, Envoy stops accepting new connections and
#   gives in-flight requests (and TCP keepalive on idle HTTP) 60s to settle
#   before exit. Default is 600s which is longer than ECS stopTimeout (max
#   120s), so without this Envoy gets SIGKILL'd mid-drain.
# --drain-strategy gradual: ramp connection-close probability over the
#   drain window instead of immediate close on first response, smoothing
#   reconnect pressure on the upstream.
#
# Pair with ECS task stopTimeout=120 (set in the api-key-proxy CDK proxy
# stack) to give the 60s drain budget room to actually complete.
# WS connections are closed by TCP FIN — clients see 1006 Abnormal Closure
# and reconnect via SDK. Cleaner 1001 Going Away would need a WASM filter
# to inject the close frame; tracked as follow-up.
exec envoy -c /envoy/envoy_subst.yaml \
  --log-level ${ENVOY_LOG_LEVEL:-info} \
  --drain-time-s 60 \
  --drain-strategy gradual
