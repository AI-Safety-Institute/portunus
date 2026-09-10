"""CloudWatch EMF emission + the server's metrics-reporter collection."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from portunus.grpc.server import _collect_metrics, _counter_snapshot
from portunus.metrics import emit_metrics
from portunus.services.publish_queue import BoundedPublishQueue


def _read_emf_line(capsys) -> dict:
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert len(lines) == 1, lines
    return json.loads(lines[0])


def test_emit_metrics_writes_valid_emf_document(capsys):
    emit_metrics(
        {"PublishedRecords": 5, "PublishQueueBytes": 1024},
        units={"PublishQueueBytes": "Bytes"},
    )
    doc = _read_emf_line(capsys)

    # Metric values are top-level fields, referenced by the _aws directive.
    assert doc["PublishedRecords"] == 5
    assert doc["PublishQueueBytes"] == 1024

    directive = doc["_aws"]["CloudWatchMetrics"][0]
    assert directive["Namespace"] == "portunus-proxy"
    assert directive["Dimensions"] == [[]]
    units = {m["Name"]: m["Unit"] for m in directive["Metrics"]}
    assert units == {"PublishedRecords": "Count", "PublishQueueBytes": "Bytes"}
    assert isinstance(doc["_aws"]["Timestamp"], int)


def test_emit_metrics_with_no_metrics_is_a_noop(capsys):
    emit_metrics({})
    assert capsys.readouterr().out == ""


async def _noop_sender(stream: str, records: list) -> int:
    return 0


@pytest.mark.asyncio
async def test_collect_metrics_reports_deltas_not_cumulative_totals():
    queue = BoundedPublishQueue(maxsize=10, num_workers=1, batch_sender=_noop_sender)
    auth = SimpleNamespace(check_allowed_total=10, check_denied_total=2)
    proc = SimpleNamespace(active_stream_count=3)

    last = _counter_snapshot(queue, auth)  # type: ignore[arg-type]
    auth.check_allowed_total = 17
    auth.check_denied_total = 5

    metrics, snapshot = _collect_metrics(queue, proc, auth, last)  # type: ignore[arg-type]

    # Counters are per-interval deltas.
    assert metrics["CheckAllowed"] == 7
    assert metrics["CheckDenied"] == 3
    assert metrics["PublishedRecords"] == 0
    # Gauges are point-in-time.
    assert metrics["ActiveExtProcStreams"] == 3
    assert metrics["PublishQueueDepth"] == 0
    assert metrics["PublishQueueBytes"] == 0
    # The returned snapshot becomes the next tick's baseline.
    assert snapshot["CheckAllowed"] == 17


@pytest.mark.asyncio
async def test_check_outcome_counters_track_allow_and_deny(monkeypatch):
    """Check() classifies its own responses so the reporter can emit them."""
    from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2

    import portunus.config as portunus_config
    from portunus.grpc.auth_servicer import PortunusAuthServicer

    monkeypatch.setattr(portunus_config.config.grpc, "proxy_api_key", "")
    servicer = PortunusAuthServicer(
        auth_service=None,  # type: ignore[arg-type]
        sign_request_fn=None,  # type: ignore[arg-type]
    )

    request = external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(
                http=attribute_context_pb2.AttributeContext.HttpRequest(id="req-m-1")
            )
        )
    )

    class _Ctx:
        def invocation_metadata(self):
            return []

    # No authorization header → the real _auth_pass denies.
    await servicer.Check(request, _Ctx())
    assert (servicer.check_allowed_total, servicer.check_denied_total) == (0, 1)

    async def fake_allow(request, context, request_id):
        return external_auth_pb2.CheckResponse()

    monkeypatch.setattr(servicer, "_auth_pass", fake_allow)
    await servicer.Check(request, _Ctx())
    assert (servicer.check_allowed_total, servicer.check_denied_total) == (1, 1)
