# Envoy 1.36 LTS — required for ext_proc FULL_DUPLEX_STREAMED + graceful
# side-stream closing (FDS requires >=1.34).
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
ENV ENVOY_LOG_LEVEL=info

COPY entrypoint.sh /envoy/entrypoint.sh
RUN chmod +x /envoy/entrypoint.sh
CMD ["/envoy/entrypoint.sh"]
