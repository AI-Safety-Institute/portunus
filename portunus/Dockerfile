FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df as builder

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

RUN mkdir -p /app && chown -R 1000:1000 /app
USER 1000:1000

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY portunus ./portunus
COPY logconf.yaml .
ENV LISTEN_PORT=8080
ENV LOG_LEVEL=info
EXPOSE 8080

CMD uvicorn portunus.app:portunus --proxy-headers --host 0.0.0.0 --port ${LISTEN_PORT} --log-level ${LOG_LEVEL} --log-config logconf.yaml --loop asyncio  --no-access-log
