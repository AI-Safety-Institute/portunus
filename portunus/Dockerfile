# Base images digest-pinned for supply-chain posture.
FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df as builder

# uv pinned by version + digest — :latest is a moving tag and the build
# toolchain is inside the trust boundary.
COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /uvx /bin/
RUN apk add gcc python3-dev libc-dev build-base linux-headers

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN touch README.md

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df as runtime

# grpc_health_probe: static binary docker/ECS use to probe the
# grpc.health.v1.Health service (Portunus serves only gRPC). musl-compatible;
# --checksum content-addresses the pin, so bumping the version requires
# updating the checksum in the same change.
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.36
ADD --checksum=sha256:1335e83e90eafc602303ca2e2501a11b5e26e69891007e4175362674669630c1 \
    --chmod=0755 \
    https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 \
    /usr/local/bin/grpc_health_probe

RUN mkdir -p /app && chown -R 1000:1000 /app
USER 1000:1000

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY portunus ./portunus
# gRPC listen port the server binds and the health probe targets.
ENV GRPC_PORT=9000
ENV LOG_LEVEL=info
# Unbuffered stdout/stderr so logs reach the awslogs driver in real time
# rather than being held by Python's pipe buffering until a flush.
ENV PYTHONUNBUFFERED=1
EXPOSE 9000

# grpc_health_probe exits 0 on overall SERVING; the server flips to
# NOT_SERVING at drain start, so draining tasks fail the probe promptly.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD grpc_health_probe -addr=127.0.0.1:${GRPC_PORT} || exit 1

# Deps installed with --no-install-project + source COPYed, so console scripts
# aren't generated — invoke the server as a module.
CMD ["python", "-m", "portunus.grpc.server"]
