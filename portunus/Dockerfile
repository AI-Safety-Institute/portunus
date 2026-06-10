FROM python:3.12-alpine as builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
RUN apk add gcc python3-dev libc-dev build-base linux-headers

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN touch README.md

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

FROM python:3.12-alpine as runtime

# grpc_health_probe: the standard static binary docker/ECS use to probe a
# gRPC server's grpc.health.v1.Health service. Replaces the old HTTP /ping
# probe now that Portunus serves only gRPC (no FastAPI). Fetched as a
# pinned, musl-compatible static build.
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.36
ADD --chmod=0755 \
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

CMD ["portunus-server"]
