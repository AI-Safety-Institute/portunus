"""Conversation-level Portunus tests driven by Inspect AI.

Companion to the transport-level corpus in test_http_proxy_behaviour.py. The shape
mirrors project-seal-tools/test/test_basic.py:

    @task -> Task(dataset=[Sample(...)], solver=[...], scorer=...)
    test function calls ``inspect_ai.eval(task, model=...)`` and asserts
    on the resulting log.

Tests are marked ``slow`` because they need the docker-compose stack
up (Portunus + httpbun + LocalStack) — same as the corpus tests in
``test_http_proxy_behaviour.py``. The CI lint/type-check jobs skip them; the
docker-driven CI lane runs them.

Mock backend: httpbun's ``/llm/chat/completions`` is OpenAI-SDK
compatible (supports streaming, accepts the standard chat-completions
body, returns OpenAI-shaped responses, lets the caller pin the reply
content via the ``httpbun`` request field). docker-compose already
routes the proxy upstream to ``http-bun``, so a request to
``http://localhost:8888/llm/chat/completions`` through Portunus hits
the mock with no extra wiring. Tests set ``OPENAI_BASE_URL`` and
``OPENAI_API_KEY`` accordingly.

Anthropic and Codex tests stay scaffolded behind their own gate:
httpbun's ``/llm/`` is OpenAI-only; Codex needs full tool-calling +
sandboxed exec which is out of scope for the chat-completions mock.
"""

# ruff: noqa: E501
from __future__ import annotations

import os

import inspect_ai as ia  # type: ignore[import-not-found]
import pytest
from conftest import encode_base64
from inspect_ai.dataset import Sample  # type: ignore[import-not-found]
from inspect_ai.scorer import (  # type: ignore[import-not-found]
    includes,
    model_graded_qa,
)
from inspect_ai.solver import generate  # type: ignore[import-not-found]

PROXY_BASE_URL = "http://localhost:8888"
HTTPBUN_LLM_PATH = "/llm"


def _portunus_openai_env() -> dict[str, str]:
    """Build the env vars the openai SDK reads to talk through Portunus."""
    bearer_payload = encode_base64({"credentials": {}, "secret_arn": ""})
    return {
        "OPENAI_BASE_URL": f"{PROXY_BASE_URL}{HTTPBUN_LLM_PATH}",
        "OPENAI_API_KEY": bearer_payload,
    }


# Anthropic + Codex tests need a different mock surface — they stay gated
# behind PORTUNUS_INSPECT_MOCK_READY because httpbun only mocks OpenAI's
# chat-completions API.
_INSPECT_MOCK_AVAILABLE = os.environ.get("PORTUNUS_INSPECT_MOCK_READY") == "1"
_skip_until_mock = pytest.mark.skipif(
    not _INSPECT_MOCK_AVAILABLE,
    reason=(
        "Requires a mock backend for Anthropic / Codex tooling. "
        "Set PORTUNUS_INSPECT_MOCK_READY=1 once one is in place."
    ),
)


@pytest.mark.slow
def test_openai_sdk_through_portunus_completes_a_chat_completion(
    docker_setup,
    monkeypatch,
) -> None:
    """OpenAI SDK through Portunus completes a chat.completion end-to-end.

    Inspect's openai/ provider reads OPENAI_BASE_URL + OPENAI_API_KEY;
    we point those at Portunus, which forwards to httpbun's
    ``/llm/chat/completions`` mock. End-to-end this proves the gRPC
    ext_authz + ext_proc pipeline doesn't break the SDK contract.
    """
    for k, v in _portunus_openai_env().items():
        monkeypatch.setenv(k, v)

    @ia.task
    def _basic_through_portunus() -> ia.Task:
        return ia.Task(
            dataset=[Sample(input="Say the word 'ready'.", target="ready")],
            solver=[generate()],
            scorer=includes(),
        )

    log = ia.eval(_basic_through_portunus, model="openai/gpt-4o-mini")[0]

    assert log.status == "success"


@_skip_until_mock
def test_anthropic_sdk_through_portunus_completes_a_message() -> None:
    """Same shape, Anthropic SDK + mock-Anthropic upstream through Portunus."""

    @ia.task
    def _basic_through_portunus_anthropic() -> ia.Task:
        return ia.Task(
            dataset=[Sample(input="Say the word 'ready'.", target="ready")],
            solver=[generate()],
            scorer=includes(),
        )

    log = ia.eval(
        _basic_through_portunus_anthropic, model="anthropic/claude-sonnet-4-6"
    )[0]

    assert log.status == "success"


@_skip_until_mock
def test_codex_cli_runs_a_multi_turn_session_through_portunus() -> None:
    """Codex CLI multi-turn session completes through Portunus.

    The OpenAI Codex CLI runs a multi-turn session against the mock
    OpenAI upstream via Portunus. This is the regression we want to
    prevent re-shipping — Codex was the first WS client and broke at
    the last rollout. Uses inspect_swe's pre-built codex_cli solver.
    """
    # inspect_swe is not a declared dependency: this branch only runs
    # when PORTUNUS_INSPECT_MOCK_READY=1 against an env that ships it.
    from inspect_swe import codex_cli  # type: ignore[import-not-found]

    @ia.task
    def _codex_through_portunus() -> ia.Task:
        return ia.Task(
            dataset=[
                Sample(
                    input="Create a hello-world.txt file containing the word 'hello'.",
                    target="A file named hello-world.txt was created.",
                )
            ],
            solver=codex_cli(),
            scorer=model_graded_qa(),
            sandbox="docker",
        )

    log = ia.eval(_codex_through_portunus, model="openai/gpt-4o-mini")[0]
    assert log.status == "success"
