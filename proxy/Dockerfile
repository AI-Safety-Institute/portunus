# ---- Builder: compile the Lua rocks and fetch yq ----
# Kept on the same Envoy base so the compiled rock (sha2.so) is ABI-compatible
# with the runtime image's embedded LuaJIT.
FROM envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb AS builder

# luarocks (and the C toolchain its recommends pull in) builds the native rocks;
# wget fetches yq. None of this reaches the runtime image.
RUN apt-get update && \
    apt-get install -y luarocks wget && \
    rm -rf /var/lib/apt/lists/*

# Install yq (YAML processor) from GitHub releases, verifying its checksum.
# TARGETARCH is amd64/arm64 depending on the platform being built.
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64) YQ_SHA256=1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0 ;; \
      arm64) YQ_SHA256=05df1f6aed334f223bb3e6a967db259f7185e33650c3b6447625e16fea0ed31f ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    wget "https://github.com/mikefarah/yq/releases/download/v4.47.2/yq_linux_${TARGETARCH}" -O /usr/bin/yq && \
    echo "${YQ_SHA256}  /usr/bin/yq" | sha256sum -c - && \
    chmod +x /usr/bin/yq

# Build and install the proxy-utils library into /usr/local/{share,lib}/lua/5.1
COPY lib /tmp/proxy-utils-lib
WORKDIR /tmp/proxy-utils-lib
RUN luarocks-5.1 make proxy-utils-1.0-0.rockspec
WORKDIR /

# ---- Runtime: clean Envoy image with only what's needed at run time ----
FROM envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb

# gettext-base provides envsubst; wget is REQUIRED at runtime — entrypoint.sh
# drives the SIGTERM drain through the Envoy admin API with it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gettext-base wget && \
    rm -rf /var/lib/apt/lists/*

# Bring over the built Lua modules (Envoy's embedded LuaJIT finds them on its
# default /usr/local/{share,lib}/lua/5.1 search paths) and the yq binary.
COPY --from=builder /usr/local/share/lua/5.1/ /usr/local/share/lua/5.1/
COPY --from=builder /usr/local/lib/lua/5.1/ /usr/local/lib/lua/5.1/
COPY --from=builder /usr/bin/yq /usr/bin/yq

# Copy the Envoy configuration files
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
