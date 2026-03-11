# Contributing

## Setup

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
uv sync
```

## Running locally

```bash
docker compose up --build
```

The proxy points at an included [httpbun](https://httpbun.com/) instance. Send a test request:

```bash
curl -X GET http://localhost:8888/headers \
  -H "Authorization: Bearer eyJjcmVkZW50aWFscyI6eyJhY2Nlc3Nfa2V5X2lkIjoiQUtJQVRFU1QiLCJzZWNyZXRfYWNjZXNzX2tleSI6IlNFQ1JFVFRFU1QiLCJzZXNzaW9uX3Rva2VuIjoiVEVTVFRPS0VOIn0sInNlY3JldF9hcm4iOiJhcm46YXdzOnNlY3JldHNtYW5hZ2VyOnVzLWVhc3QtMToxMjM0NTY3ODkwMTI6c2VjcmV0OnRlc3Qtc2VjcmV0In0="
```

## Tests

```bash
# Unit tests
uv run pytest portunus/tests/

# E2E tests (requires docker compose stack)
docker compose up --build --wait
uv run pytest tests/

# Lua tests
cd proxy && busted lib/spec/
```

## Linting & type checking

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy portunus/ tests/
```
