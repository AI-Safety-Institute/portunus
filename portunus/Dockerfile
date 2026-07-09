# Base images digest-pinned (supply-chain posture from #31, carried into
# this rewritten multi-stage build).
FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df as builder

# uv pinned by version + digest — ``:latest`` is a moving tag and the
# build toolchain is inside the trust boundary (#31 posture).
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

# grpc_health_probe: the standard static binary docker/ECS use to probe a
# gRPC server's grpc.health.v1.Health service. Replaces the old HTTP /ping
# probe now that Portunus serves only gRPC (no FastAPI). Fetched as a
# pinned, musl-compatible static build; ``--checksum`` makes the pin
# content-addressed rather than tag-addressed (a release tag's assets can
# be replaced; the digest can't). Bumping GRPC_HEALTH_PROBE_VERSION
# requires updating the checksum in the same change.
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
# gRPC listen port (loopback in the sidecar topology). GRPC_PORT is what the
# server binds and the health probe targets.
ENV GRPC_PORT=9000
ENV LOG_LEVEL=info
# Force unbuffered stdout/stderr so logs land in CloudWatch in real time
# rather than being held by the Python runtime's pipe buffering — otherwise
# gRPC-server boot logs never reach the awslogs driver until the buffer
# happens to flush, making "is the service alive?" impossible from logs.
ENV PYTHONUNBUFFERED=1
EXPOSE 9000

# Probe the gRPC health service so the orchestrator can tell whether the
# server is serving. grpc_health_probe exits 0 on overall SERVING; the
# server flips to NOT_SERVING at the start of graceful drain, so draining
# tasks fail the probe promptly.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD grpc_health_probe -addr=127.0.0.1:${GRPC_PORT} || exit 1

# The image installs deps only (uv sync --no-install-project) and COPYs the
# package source, so the project's console scripts aren't generated — invoke
# the server as a module instead.
CMD ["python", "-m", "portunus.grpc.server"]
