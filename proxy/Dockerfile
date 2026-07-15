# Envoy 1.38 LTS. >= 1.36 required for the ext_proc observability_mode +
# STREAMED body-mode combination and HttpRequestHeaderMatchInput in the
# composite signing gate; also carries the fix for the 1.31 shutdown SIGSEGV
# under in-flight AsyncClient streams. Do NOT drop back to v1.31.x. Digest-pinned.
FROM envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb

# Assert the base image is the Envoy this config was qualified against: 1.31
# boots cleanly and passes health checks, so the regression only shows up as
# the nondeterministic shutdown SIGSEGV. entrypoint.sh re-asserts at runtime.
RUN envoy --version && envoy --version | grep -q '/1\.38\.'

# gettext for envsubst; wget fetches yq AND is REQUIRED at runtime — the
# entrypoint drives the SIGTERM drain through the admin API with it. If this
# image ever goes multi-stage, wget must stay in the runtime stage.
RUN apt update && apt install -y gettext wget

# yq — entrypoint.sh uses it to synthesise transport socket configs as
# JSON-encoded env vars. Checksummed: an unverified release download is a
# supply-chain hole.
RUN wget https://github.com/mikefarah/yq/releases/download/v4.47.2/yq_linux_amd64 -O /usr/bin/yq && \
    echo "1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0  /usr/bin/yq" | sha256sum -c - && \
    chmod +x /usr/bin/yq

COPY envoy.yaml /envoy/envoy.yaml
COPY xray.json /envoy/xray.json

RUN chown -R envoy:envoy /envoy

# Defaults for envsubst variables (overridable via the container env).
# envsubst doesn't support ${X:-default}, so defaults live here.
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
