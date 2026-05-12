"""Conversation-level Portunus tests driven by Inspect AI.

Companion to the transport-level corpus in test_behaviours.py. The shape
mirrors project-seal-tools/test/test_basic.py:

    @task -> Task(dataset=[Sample(...)], solver=[...], scorer=...)
    test function calls ``inspect_ai.eval(task, model=...)`` and asserts
    on the resulting log.

This file is the **scaffold** — every test currently skips because
running these end-to-end requires an OpenAI-shaped mock upstream that
returns OpenAI-format responses (so the SDK can parse them). Real
OpenAI / Anthropic upstreams aren't acceptable (real API credits, real
keys, breaks the no-real-upstream-from-executor constraint).

When the mock OpenAI upstream PR lands:
  1. Add ``inspect-ai`` and ``inspect-swe`` to the dev dependency group
     in pyproject.toml.
  2. Drop the skip markers below.
  3. Configure OPENAI_BASE_URL / ANTHROPIC_BASE_URL to point at Portunus
     in the test environment (already routed to the mock upstream via
     Portunus's ``TARGET_HOST`` for those proxies).
  4. Add more tasks: multi-turn conversation, streaming, tool use,
     reasoning content. Pattern is identical to seal-tools/test_basic.py.
"""

# ruff: noqa: E501
from __future__ import annotations

import os

import pytest

_INSPECT_MOCK_AVAILABLE = os.environ.get("PORTUNUS_INSPECT_MOCK_READY") == "1"
_skip_until_mock = pytest.mark.skipif(
    not _INSPECT_MOCK_AVAILABLE,
    reason=(
        "Requires the OpenAI-shaped mock upstream (tracked in task #44). "
        "Set PORTUNUS_INSPECT_MOCK_READY=1 once that's deployed."
    ),
)


@_skip_until_mock
def test_openai_sdk_through_portunus_completes_a_chat_completion() -> None:
    """Pointed at Portunus -> mock-OpenAI upstream, the openai SDK
    completes ``chat.completions.create`` end-to-end."""
    import inspect_ai as ia  # type: ignore[import-not-found]
    from inspect_ai.dataset import Sample  # type: ignore[import-not-found]
    from inspect_ai.scorer import includes  # type: ignore[import-not-found]
    from inspect_ai.solver import generate  # type: ignore[import-not-found]

    @ia.task
    def _basic_through_portunus() -> ia.Task:
        return ia.Task(
            dataset=[Sample(input="Say the word 'ready'.", target="ready")],
            solver=[generate()],
            scorer=includes(),
        )

    # OPENAI_BASE_URL is expected to be set to Portunus's OpenAI proxy
    # URL by the test environment. Inspect's openai/ provider will pick
    # it up.
    log = ia.eval(_basic_through_portunus, model="openai/gpt-4o-mini")[0]

    assert log.status == "success"


@_skip_until_mock
def test_anthropic_sdk_through_portunus_completes_a_message() -> None:
    """Same shape, Anthropic SDK + mock-Anthropic upstream through Portunus."""
    import inspect_ai as ia  # type: ignore[import-not-found]
    from inspect_ai.dataset import Sample  # type: ignore[import-not-found]
    from inspect_ai.scorer import includes  # type: ignore[import-not-found]
    from inspect_ai.solver import generate  # type: ignore[import-not-found]

    @ia.task
    def _basic_through_portunus_anthropic() -> ia.Task:
        return ia.Task(
            dataset=[Sample(input="Say the word 'ready'.", target="ready")],
            solver=[generate()],
            scorer=includes(),
        )

    log = ia.eval(_basic_through_portunus_anthropic, model="anthropic/claude-sonnet-4-6")[0]

    assert log.status == "success"


@_skip_until_mock
def test_codex_cli_runs_a_multi_turn_session_through_portunus() -> None:
    """The OpenAI Codex CLI completes a multi-turn session against the
    mock OpenAI upstream via Portunus. This is the regression we want to
    prevent re-shipping - Codex was the first WS client and broke at the
    last rollout. Uses inspect_swe's pre-built codex_cli solver."""
    import inspect_ai as ia  # type: ignore[import-not-found]
    from inspect_ai.dataset import Sample  # type: ignore[import-not-found]
    from inspect_ai.scorer import model_graded_qa  # type: ignore[import-not-found]
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
