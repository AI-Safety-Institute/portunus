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

import uuid

from envoy.config.core.v3 import base_pb2
from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2
from envoy.service.ext_proc.v3 import external_processor_pb2 as proc_pb2

from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.grpc.proc_servicer import _extract_request_id as _proc_extract_request_id

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
