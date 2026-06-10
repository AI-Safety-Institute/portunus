# Envoy 1.36 LTS — required for the maturity of the ext_proc
# observability_mode + STREAMED body-mode combination this proxy uses,
# and for HttpRequestHeaderMatchInput in the composite-filter signing
# gate.
FROM envoyproxy/envoy:v1.36.0

# gettext for envsubst (used in entrypoint.sh), wget for the yq binary.
RUN apt update && apt install -y gettext wget

# yq (YAML processor) — entrypoint.sh uses it to synthesise transport
# socket configs as JSON-encoded env vars.
RUN wget https://github.com/mikefarah/yq/releases/download/v4.47.2/yq_linux_amd64 -O /usr/bin/yq && \
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
    PORTUNUS_GRPC_PORT=9000

COPY entrypoint.sh /envoy/entrypoint.sh
RUN chmod +x /envoy/entrypoint.sh
CMD ["/envoy/entrypoint.sh"]
