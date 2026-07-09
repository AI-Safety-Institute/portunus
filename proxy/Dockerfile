# Envoy 1.36 LTS — required for the maturity of the ext_proc
# observability_mode + STREAMED body-mode combination this proxy uses,
# and for HttpRequestHeaderMatchInput in the composite-filter signing
# gate. Also the fix for the 1.31 shutdown SIGSEGV under in-flight
# AsyncClient streams that #34/#35 were raised to eliminate — do NOT
# resolve any merge conflict on this line back to v1.31.x (the version
# assertion below turns that mistake into a build failure). Digest-pinned
# (supply-chain posture from #31, re-resolved for 1.36).
FROM envoyproxy/envoy:v1.36.0@sha256:d62f60a74cd9631b28bb3f538788ccff201b226975179de4265b0d75fc347e90

# Assert the resolved base image really is the Envoy this config was
# qualified against. Catches a careless #31↔#34 FROM-line conflict
# resolution (1.31 boots this config cleanly and passes every health
# check — the regression only shows up as the nondeterministic shutdown
# SIGSEGV). entrypoint.sh re-asserts at runtime.
RUN envoy --version && envoy --version | grep -q '/1\.36\.'

# gettext for envsubst (used in entrypoint.sh), wget for the yq binary.
RUN apt update && apt install -y gettext wget

# yq (YAML processor) — entrypoint.sh uses it to synthesise transport
# socket configs as JSON-encoded env vars. Checksummed: a release
# download with no integrity check is a supply-chain hole (#31 posture).
RUN wget https://github.com/mikefarah/yq/releases/download/v4.47.2/yq_linux_amd64 -O /usr/bin/yq && \
    echo "1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0  /usr/bin/yq" | sha256sum -c - && \
    chmod +x /usr/bin/yq

COPY envoy.yaml /envoy/envoy.yaml
COPY xray.json /envoy/xray.json

RUN chown -R envoy:envoy /envoy

# Defaults for envsubst variables. These can be overridden via the
# container's environment (docker-compose, ECS task definition, etc.).
# envsubst itself doesn't support ``${X:-default}`` syntax, so defaults
# live here rather than in entrypoint.sh or envoy.yaml.
ENV ENVOY_LOG_LEVEL=info \
    LISTEN_PORT=8888 \
    RATE_LIMIT_REQUESTS_PER_INTERVAL=1 \
    RATE_LIMIT_INTERVAL_SECONDS=1 \
    RATE_LIMIT_PERCENT_ENABLED=0 \
    TARGET_MAX_CONNECTIONS=10000 \
    TARGET_HOST_USE_TLS=true \
    PORTUNUS_HEADER_PREFIX=portunus \
    PORTUNUS_HOST=127.0.0.1 \
    PORTUNUS_GRPC_PORT=9000 \
    ADMIN_PORT=9901 \
    DRAIN_TIME_S=60

COPY entrypoint.sh /envoy/entrypoint.sh
RUN chmod +x /envoy/entrypoint.sh
CMD ["/envoy/entrypoint.sh"]
