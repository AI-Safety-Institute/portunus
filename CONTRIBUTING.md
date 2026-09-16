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
TOKEN=$(python - <<'PY'
import base64
import json

payload = {
    "credentials": {
        "access_key_id": "000000000000",
        "secret_access_key": "test",
        "session_token": "test",
    },
    "secret_arn": "arn:aws:secretsmanager:eu-west-2:000000000000:secret:test-api-key",
}
print(base64.b64encode(json.dumps(payload).encode()).decode())
PY
)
curl http://localhost:8888/headers -H "Authorization: Bearer $TOKEN"
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

Versioning is handled automatically by [hatch-vcs](https://github.com/ofek/hatch-vcs) from git tags. Choose the next release tag in `RELEASE_TAG`, then create a release:

```bash
git tag "$RELEASE_TAG"
git push origin "$RELEASE_TAG"
```

A GitHub Actions workflow will create a GitHub release with auto-generated notes. If the release already exists (e.g. created via `gh release create`), the workflow skips gracefully.

## Linting and type checking

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy portunus/ tests/
```
