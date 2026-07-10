# Start from the (Debian-based) Envoy image
FROM envoyproxy/envoy:v1.31.0@sha256:2bf7f042e3960e3904864cb09c174498e20a06859a5c394b7e3a6528a649b1da

# gettext provides envsubst (used at runtime by entrypoint.sh); luarocks builds
# the Lua library (and pulls the C toolchain it needs to compile native rocks);
# wget fetches yq. Cleaning the apt lists keeps the image free of stale metadata.
RUN apt-get update && \
    apt-get install -y gettext luarocks wget && \
    rm -rf /var/lib/apt/lists/*

# Install yq (YAML processor) from GitHub releases, verifying its checksum
RUN wget https://github.com/mikefarah/yq/releases/download/v4.47.2/yq_linux_amd64 -O /usr/bin/yq && \
    echo "1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0  /usr/bin/yq" | sha256sum -c - && \
    chmod +x /usr/bin/yq

# Copy and install the proxy-utils library (dependencies declared in rockspec)
COPY lib /tmp/proxy-utils-lib
WORKDIR /tmp/proxy-utils-lib
RUN luarocks-5.1 make proxy-utils-1.0-0.rockspec
WORKDIR /

# Copy the Envoy configuration file to the Docker image
COPY envoy.yaml /envoy/envoy.yaml
COPY lua.lua /envoy/lua.lua
COPY xray.json /envoy/xray.json

RUN chown -R envoy:envoy /envoy
ENV ENVOY_LOG_LEVEL=info

COPY entrypoint.sh /envoy/entrypoint.sh
RUN chmod +x /envoy/entrypoint.sh

# Drop root — Envoy only needs to bind the non-privileged LISTEN_PORT (8888),
# and entrypoint.sh writes its rendered config under /envoy (owned by envoy).
USER envoy
CMD ["/envoy/entrypoint.sh"]
