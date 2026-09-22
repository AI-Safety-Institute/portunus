FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN touch README.md

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project
RUN .venv/bin/python -c "from google.protobuf.internal import api_implementation; assert api_implementation.Type() == 'upb', 'native protobuf backend required'"

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS runtime

RUN mkdir -p /app && chown -R 1000:1000 /app
USER 1000:1000

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY portunus ./portunus
COPY logconf.yaml .
ENV LISTEN_PORT=8080
ENV LOG_LEVEL=info
# One uvicorn worker uses at most one core; deployments on multi-vCPU hosts
# should set this to the vCPU count to use the full allocation.
ENV UVICORN_WORKERS=1
EXPOSE 8080

CMD uvicorn portunus.app:portunus --proxy-headers --host 0.0.0.0 --port ${LISTEN_PORT} --workers ${UVICORN_WORKERS} --log-level ${LOG_LEVEL} --log-config logconf.yaml --loop asyncio --no-access-log
