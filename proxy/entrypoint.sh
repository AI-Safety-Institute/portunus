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
if [ -z "$PORTUNUS_TRANSPORT_SOCKET" ]; then
  export PORTUNUS_TRANSPORT_SOCKET=$(yq -o json <<EOF
name: envoy.transport_sockets.tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
  sni: $PORTUNUS_HOST
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

# Start Envoy with the substituted config
exec envoy -c /envoy/envoy_subst.yaml --log-level ${ENVOY_LOG_LEVEL:-info}
