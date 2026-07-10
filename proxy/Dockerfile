# Start from the Envoy Alpine Linux image
FROM envoyproxy/envoy:v1.31.0@sha256:2bf7f042e3960e3904864cb09c174498e20a06859a5c394b7e3a6528a649b1da

# Update the package lists
RUN apt update

# Install gettext for envsubst and luarocks
RUN apt install -y gettext luarocks wget

# Install yq (YAML processor) from GitHub releases
RUN wget https://github.com/mikefarah/yq/releases/download/v4.47.2/yq_linux_amd64 -O /usr/bin/yq && \
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
CMD ["/envoy/entrypoint.sh"]
