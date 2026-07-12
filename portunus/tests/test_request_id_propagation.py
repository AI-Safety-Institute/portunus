"""request_id propagation across ext_authz + ext_proc.

Replaces the removed FastAPI/uvicorn ``test_trace_propagation.py``. That test
guarded a uvicorn-import-ordering bug that broke X-Ray trace-ids and collapsed
every proxy log into a single ``request_id`` group, OOMing the joined-logs ETL
(2026-07-02 outage). The FastAPI/uvicorn serving stack is gone; request_id now
comes from Envoy's ``x-request-id`` (surfaced to ext_authz as
``attributes.request.http.id`` and to ext_proc as the ``x-request-id`` header).

The failure *mechanism* changed but the failure *class* didn't: if request_id
stopped propagating — or worse, fell back to a shared constant — records would
re-collapse into one group and re-OOM the ETL. These tests lock the two
properties that prevent that:

1. both servicers extract the *same* id Envoy assigned a request (so
   ext_authz metadata and ext_proc body/header records correlate); and
2. a request with no id gets a fresh, unique UUID per request — never a shared
   placeholder (``""`` / ``"No-Trace-Id"`` / a fixed string).
"""

from __future__ import annotations

import json
import logging
import uuid

import pytest
from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2

import portunus.config as portunus_config
import portunus.grpc.auth_servicer as auth_servicer_mod
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.grpc.proc_servicer import PortunusProcessServicer
from portunus.grpc.proc_servicer import _extract_request_id as _proc_extract_request_id
from portunus.services.xray_service import request_id_var, trace_id_var

_auth_extract_request_id = PortunusAuthServicer._extract_request_id


def _auth_check_request(request_id: str) -> external_auth_pb2.CheckRequest:
    """ext_authz CheckRequest with Envoy's ``http.id`` set (empty = unset)."""
    return external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(
                http=attribute_context_pb2.AttributeContext.HttpRequest(id=request_id)
            )
        )
    )


def _proc_headers_request(request_id: str | None) -> proc_pb2.ProcessingRequest:
    """ext_proc request_headers message, with ``x-request-id`` iff given."""
    headers = []
    if request_id is not None:
        headers.append(base_pb2.HeaderValue(key="x-request-id", value=request_id))
    return proc_pb2.ProcessingRequest(
        request_headers=proc_pb2.HttpHeaders(
            headers=base_pb2.HeaderMap(headers=headers), end_of_stream=False
        )
    )


def _assert_minted_uuid(value: str) -> None:
    """A minted id must be a real UUID, not a shared placeholder."""
    assert value not in ("", "No-Trace-Id", "None", "unknown"), value
    # Raises ValueError if not a well-formed UUID.
    uuid.UUID(value)


def test_auth_extracts_envoy_request_id() -> None:
    assert _auth_extract_request_id(_auth_check_request("req-abc-123")) == "req-abc-123"


def test_proc_extracts_x_request_id_header() -> None:
    got = _proc_extract_request_id(_proc_headers_request("req-abc-123"))
    assert got == "req-abc-123"


def test_both_servicers_agree_on_the_same_envoy_id() -> None:
    """Joined-logs guard: ext_authz and ext_proc resolve the same Envoy id."""
    envoy_id = "1a2b3c4d-aaaa-bbbb-cccc-000000000001"
    auth_id = _auth_extract_request_id(_auth_check_request(envoy_id))
    proc_id = _proc_extract_request_id(_proc_headers_request(envoy_id))
    assert auth_id == proc_id == envoy_id


def test_auth_missing_id_mints_unique_uuid_not_placeholder() -> None:
    a = _auth_extract_request_id(_auth_check_request(""))
    b = _auth_extract_request_id(_auth_check_request(""))
    _assert_minted_uuid(a)
    _assert_minted_uuid(b)
    # Distinct requests must not collapse onto one group.
    assert a != b


def test_proc_missing_id_mints_unique_uuid_not_placeholder() -> None:
    # No x-request-id header at all, and the degenerate empty-value case.
    a = _proc_extract_request_id(_proc_headers_request(None))
    b = _proc_extract_request_id(_proc_headers_request(""))
    c = _proc_extract_request_id(_proc_headers_request(None))
    for v in (a, b, c):
        _assert_minted_uuid(v)
    assert len({a, b, c}) == 3, (a, b, c)


def test_proc_non_headers_first_message_still_mints_unique() -> None:
    """A body-first stream (no headers message) still gets a unique id."""
    body_only = proc_pb2.ProcessingRequest(
        request_body=proc_pb2.HttpBody(body=b"x", end_of_stream=True)
    )
    a = _proc_extract_request_id(body_only)
    b = _proc_extract_request_id(body_only)
    _assert_minted_uuid(a)
    _assert_minted_uuid(b)
    assert a != b


# ---------------------------------------------------------------------------
# Correlation contextvars: gRPC entry points bind them; the log formatter
# emits them (and omits them when unset — never a shared placeholder).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_correlation_vars():
    yield
    request_id_var.set(None)
    trace_id_var.set(None)


class _FakeGrpcContext:
    def invocation_metadata(self):
        return []


def _auth_request_with_headers(
    request_id: str, headers: dict[str, str]
) -> external_auth_pb2.CheckRequest:
    return external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(
                http=attribute_context_pb2.AttributeContext.HttpRequest(
                    id=request_id, headers=headers
                )
            )
        )
    )


def _make_auth_servicer() -> PortunusAuthServicer:
    return PortunusAuthServicer(
        auth_service=None,  # type: ignore[arg-type]  # Check path stubbed per-test
        sign_request_fn=None,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_check_binds_request_id_contextvar(monkeypatch):
    """Every log line inside Check must be attributable: Check sets the var."""
    monkeypatch.setattr(portunus_config.config.grpc, "proxy_api_key", "")
    servicer = _make_auth_servicer()
    seen: dict[str, str | None] = {}

    async def fake_auth_pass(request, context, request_id):
        seen["ctxvar"] = request_id_var.get()
        return "handled"

    monkeypatch.setattr(servicer, "_auth_pass", fake_auth_pass)
    result = await servicer.Check(
        _auth_request_with_headers("req-ctx-1", {}), _FakeGrpcContext()
    )
    assert result == "handled"
    assert seen["ctxvar"] == "req-ctx-1"


@pytest.mark.asyncio
async def test_check_opens_xray_segment_from_envoy_trace_header(monkeypatch):
    """With X-Ray enabled, Check joins the trace Envoy propagates."""
    monkeypatch.setattr(portunus_config.config.grpc, "proxy_api_key", "")
    monkeypatch.setattr(portunus_config.config.aws, "xray_enabled", True)
    calls: list[dict] = []

    class FakeXRayContext:
        def __init__(self, trace_id, segment_name=None, parent_id=None, sampled=None):
            calls.append(
                dict(
                    trace_id=trace_id,
                    segment_name=segment_name,
                    parent_id=parent_id,
                    sampled=sampled,
                )
            )

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(auth_servicer_mod, "XRayContext", FakeXRayContext)
    servicer = _make_auth_servicer()

    async def fake_auth_pass(request, context, request_id):
        return "handled"

    monkeypatch.setattr(servicer, "_auth_pass", fake_auth_pass)
    trace_header = (
        "Root=1-6800aa2c-abcdef012345678912345678;" "Parent=53995c3f42cd8ad8;Sampled=1"
    )
    result = await servicer.Check(
        _auth_request_with_headers("req-ctx-2", {"x-amzn-trace-id": trace_header}),
        _FakeGrpcContext(),
    )
    assert result == "handled"
    assert calls == [
        dict(
            trace_id="1-6800aa2c-abcdef012345678912345678",
            segment_name="portunus-ext-authz",
            parent_id="53995c3f42cd8ad8",
            sampled=True,
        )
    ]


@pytest.mark.asyncio
async def test_check_sets_trace_id_var_even_with_xray_disabled(monkeypatch):
    """X-Ray off must not lose the trace id from log lines."""
    monkeypatch.setattr(portunus_config.config.grpc, "proxy_api_key", "")
    monkeypatch.setattr(portunus_config.config.aws, "xray_enabled", False)
    servicer = _make_auth_servicer()
    seen: dict[str, str | None] = {}

    async def fake_auth_pass(request, context, request_id):
        seen["trace"] = trace_id_var.get()
        return "handled"

    monkeypatch.setattr(servicer, "_auth_pass", fake_auth_pass)
    await servicer.Check(
        _auth_request_with_headers(
            "req-ctx-3", {"x-amzn-trace-id": "Root=1-abc-def;Sampled=0"}
        ),
        _FakeGrpcContext(),
    )
    assert seen["trace"] == "1-abc-def"


def test_proc_stream_init_binds_both_contextvars():
    servicer = PortunusProcessServicer(
        publish_service=None,  # type: ignore[arg-type]  # not exercised
        publish_queue=None,  # type: ignore[arg-type]
    )
    headers = base_pb2.HeaderMap(
        headers=[
            base_pb2.HeaderValue(key="x-request-id", value="req-proc-7"),
            base_pb2.HeaderValue(
                key="x-amzn-trace-id", value="Root=1-aa-bb;Parent=cc;Sampled=1"
            ),
        ]
    )
    first = proc_pb2.ProcessingRequest(
        request_headers=proc_pb2.HttpHeaders(headers=headers, end_of_stream=False)
    )
    state = servicer._initialise_stream(first)
    assert state.request_id == "req-proc-7"
    assert request_id_var.get() == "req-proc-7"
    assert trace_id_var.get() == "1-aa-bb"


def test_formatter_emits_request_id_and_omits_when_unset():
    from portunus.logging import StructuredLogFormatter

    formatter = StructuredLogFormatter()
    record = logging.LogRecord(
        name="api.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )

    request_id_var.set("req-fmt-1")
    trace_id_var.set("1-trace-9")
    with_ids = json.loads(formatter.format(record))
    assert with_ids["request_id"] == "req-fmt-1"
    assert with_ids["trace_id"] == "1-trace-9"

    request_id_var.set(None)
    trace_id_var.set(None)
    without = json.loads(formatter.format(record))
    assert "request_id" not in without
    assert "trace_id" not in without
    # The old formatter stamped a constant placeholder on every line, which
    # collapsed all logs into one correlation group. Never again.
    assert "No-Trace-Id" not in formatter.format(record)


@pytest.mark.asyncio
async def test_publish_queue_failure_logs_carry_request_id(caplog):
    """Workers log outside request context; the id must travel on the task."""
    from portunus.services.publish_queue import BoundedPublishQueue, PublishTask

    async def batch_sender(stream, records):
        return 0

    queue = BoundedPublishQueue(maxsize=10, num_workers=1, batch_sender=batch_sender)
    await queue.start()

    def bad_build():
        raise ValueError("boom")

    with caplog.at_level(logging.ERROR):
        await queue.submit_blocking(
            PublishTask(build=bad_build, label="request_body", request_id="req-q-1"),
            timeout=1.0,
        )
        await queue.stop(drain_timeout=5.0)

    build_failures = [
        r.getMessage() for r in caplog.records if "Build failed" in r.getMessage()
    ]
    assert build_failures, caplog.records
    assert any("req-q-1" in message for message in build_failures)
