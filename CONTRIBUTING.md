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

The suite has two surfaces. The fast one runs on every push; the slow one needs Docker.

```bash
# Unit tests — fast, no Docker, run in CI on every push / PR.
cd portunus && uv run pytest -q

# Behaviour + e2e tests — slow, require docker-compose, also run in CI.
docker compose up --build --wait
uv run --group dev pytest tests/ -q
```

Inside `tests/`:

- `test_http_proxy_behaviour.py` — parameterised HTTP behaviour corpus.
- `test_ws_proxy_behaviour.py` — WebSocket behaviours (upgrade, frames, close, abrupt disconnect).
- `test_e2e.py` / `test_e2e_signing.py` — non-corpus HTTP + RFC 9421 signing against Anthropic test vectors.
- `test_inspect_compat.py` — OpenAI SDK round-trip driven by Inspect AI.
- `test_redis_cache.py` — Redis cache semantics.

Tests that need the Docker stack are tagged `@pytest.mark.slow`.

## Releasing

Versioning is handled automatically by [hatch-vcs](https://github.com/ofek/hatch-vcs) from git tags. To create a release:

```bash
git tag v0.6.0
git push origin v0.6.0
```

A GitHub Actions workflow will create a GitHub release with auto-generated notes. If the release already exists (e.g. created via `gh release create`), the workflow skips gracefully.

## Linting and type checking

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy portunus/ tests/
```
