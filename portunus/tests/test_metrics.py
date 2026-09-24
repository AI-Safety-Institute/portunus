"""The in-process EMF aggregator and the server's metrics reporter."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2

import portunus.config as portunus_config
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.metrics import (
    ACTIVE_EXT_PROC_STREAMS,
    CHECK_ALLOWED,
    CHECK_DENIED,
    CHECK_LATENCY,
    EVENT_LOOP_LAG,
    PUBLISH_QUEUE_BYTES,
    PUBLISHED_RECORDS,
    MetricsAggregator,
)


def _aggregator(**kwargs) -> MetricsAggregator:
    defaults: dict = dict(
        enabled=True,
        namespace="Portunus",
        service_name="portunus-proxy",
        role="all",
    )
    defaults.update(kwargs)
    return MetricsAggregator(**defaults)


def _read_emf_lines(capsys) -> list[dict]:
    return [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.strip()
    ]


def _read_emf_line(capsys) -> dict:
    lines = _read_emf_lines(capsys)
    assert len(lines) == 1, lines
    return lines[0]


def test_flush_emits_a_valid_emf_document(capsys):
    """The flushed line must satisfy the EMF spec CloudWatch parses."""
    metrics = _aggregator(counter_names=(CHECK_ALLOWED,))
    metrics.incr(CHECK_ALLOWED, 3)
    metrics.flush()

    doc = _read_emf_line(capsys)
    assert isinstance(doc["_aws"]["Timestamp"], int)
    directive = doc["_aws"]["CloudWatchMetrics"][0]
    assert directive["Namespace"] == "Portunus"
    assert directive["Dimensions"] == [["ServiceName", "Role"]]
    # Dimension values live at the top level alongside the metric values.
    assert doc["ServiceName"] == "portunus-proxy"
    assert doc["Role"] == "all"
    assert {"Name": CHECK_ALLOWED, "Unit": "Count"} in directive["Metrics"]
    assert doc[CHECK_ALLOWED] == 3


def test_disabled_aggregator_emits_nothing(capsys):
    """METRICS_ENABLED=false must leave stdout untouched (local dev, tests)."""
    metrics = _aggregator(enabled=False, counter_names=(CHECK_ALLOWED,))
    metrics.incr(CHECK_ALLOWED, 5)
    metrics.observe(CHECK_LATENCY, 12.5)
    metrics.register_gauge_source(lambda: {ACTIVE_EXT_PROC_STREAMS: 4})
    metrics.flush()

    assert capsys.readouterr().out == ""


def test_counters_are_per_interval_deltas_and_reset(capsys):
    """CloudWatch Sum over a period must be that period's count, not a total."""
    metrics = _aggregator(counter_names=(CHECK_ALLOWED, CHECK_DENIED))
    metrics.incr(CHECK_ALLOWED, 2)
    metrics.flush()
    assert _read_emf_line(capsys)[CHECK_ALLOWED] == 2

    metrics.incr(CHECK_ALLOWED)
    metrics.flush()
    doc = _read_emf_line(capsys)
    assert doc[CHECK_ALLOWED] == 1
    # A registered counter with no activity still reports zero, so a gap in
    # the series means "task gone", not "nothing happened".
    assert doc[CHECK_DENIED] == 0


def test_delta_sources_report_the_interval_change(capsys):
    """Components that keep their own cumulative counters are diffed."""
    source = {PUBLISHED_RECORDS: 10}
    metrics = _aggregator()
    metrics.register_delta_source(lambda: dict(source))

    # The first flush baselines against the value at registration time.
    metrics.flush()
    assert _read_emf_line(capsys)[PUBLISHED_RECORDS] == 0

    source[PUBLISHED_RECORDS] = 17
    metrics.flush()
    assert _read_emf_line(capsys)[PUBLISHED_RECORDS] == 7


def test_gauge_sources_are_point_in_time(capsys):
    """Gauges are sampled at flush, never differenced."""
    metrics = _aggregator()
    metrics.register_gauge_source(
        lambda: {ACTIVE_EXT_PROC_STREAMS: 3, PUBLISH_QUEUE_BYTES: 2048}
    )
    metrics.flush()
    metrics.flush()

    docs = _read_emf_lines(capsys)
    assert [d[ACTIVE_EXT_PROC_STREAMS] for d in docs] == [3, 3]
    directive = docs[0]["_aws"]["CloudWatchMetrics"][0]
    units = {m["Name"]: m["Unit"] for m in directive["Metrics"]}
    assert units[PUBLISH_QUEUE_BYTES] == "Bytes"


def test_observations_emit_bucketed_values_and_counts(capsys):
    """Latencies ship as EMF Values/Counts, within the 100-value ceiling."""
    metrics = _aggregator()
    for _ in range(5):
        metrics.observe(CHECK_LATENCY, 3.0)
    metrics.observe(CHECK_LATENCY, 900.0)
    metrics.flush()

    doc = _read_emf_line(capsys)
    entry = doc[CHECK_LATENCY]
    values, counts = entry["Values"], entry["Counts"]
    assert len(values) == len(counts) == 2
    assert len(values) <= 100
    assert sum(counts) == 6
    # Bucket bounds are upper bounds, so an observation is never
    # under-reported and the ladder stays monotonic.
    assert values[0] >= 3.0 and values[1] >= 900.0
    assert values[0] < values[1]
    directive = doc["_aws"]["CloudWatchMetrics"][0]
    units = {m["Name"]: m["Unit"] for m in directive["Metrics"]}
    assert units[CHECK_LATENCY] == "Milliseconds"


def test_observations_reset_between_flushes(capsys):
    """A quiet interval must not replay the previous interval's histogram."""
    metrics = _aggregator()
    metrics.observe(EVENT_LOOP_LAG, 4.0)
    metrics.flush()
    assert EVENT_LOOP_LAG in _read_emf_line(capsys)

    metrics.observe(EVENT_LOOP_LAG, 4.0)
    metrics.flush()
    doc = _read_emf_line(capsys)
    assert sum(doc[EVENT_LOOP_LAG]["Counts"]) == 1


def test_flush_with_nothing_registered_emits_nothing(capsys):
    """No metrics means no line — an empty EMF document is invalid."""
    _aggregator().flush()
    assert capsys.readouterr().out == ""


def test_huge_observation_lands_in_the_overflow_bucket(capsys):
    """A pathological latency must still be counted, not dropped."""
    metrics = _aggregator()
    metrics.observe(CHECK_LATENCY, 10_000_000.0)
    metrics.flush()

    entry = _read_emf_line(capsys)[CHECK_LATENCY]
    assert sum(entry["Counts"]) == 1
    assert entry["Values"][0] > 0


def test_a_failing_source_does_not_lose_the_other_metrics(capsys):
    """Metrics must never take the process down, nor blind the rest."""

    def broken() -> dict[str, float]:
        raise RuntimeError("gauge blew up")

    metrics = _aggregator(counter_names=(CHECK_ALLOWED,))
    metrics.register_gauge_source(broken)
    metrics.incr(CHECK_ALLOWED)
    metrics.flush()

    assert _read_emf_line(capsys)[CHECK_ALLOWED] == 1


@pytest.mark.asyncio
async def test_check_outcome_counters_track_allow_and_deny(monkeypatch):
    """Check() classifies its own responses so the reporter can emit them."""
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

    async def fake_allow(request, context, request_id, headers):
        return external_auth_pb2.CheckResponse()

    monkeypatch.setattr(servicer, "_auth_pass", fake_allow)
    await servicer.Check(request, _Ctx())
    assert (servicer.check_allowed_total, servicer.check_denied_total) == (1, 1)


@pytest.mark.asyncio
async def test_check_records_outcome_metrics_and_latency(monkeypatch):
    """A denied Check reaches the aggregator with a latency sample."""
    import portunus.grpc.auth_servicer as auth_servicer_mod

    metrics = _aggregator(counter_names=(CHECK_ALLOWED, CHECK_DENIED))
    monkeypatch.setattr(auth_servicer_mod, "metrics", metrics)
    monkeypatch.setattr(portunus_config.config.grpc, "proxy_api_key", "")

    servicer = PortunusAuthServicer(
        auth_service=None,  # type: ignore[arg-type]
        sign_request_fn=None,  # type: ignore[arg-type]
    )
    request = external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(
                http=attribute_context_pb2.AttributeContext.HttpRequest(id="req-m-2")
            )
        )
    )

    class _Ctx:
        def invocation_metadata(self):
            return []

    await servicer.Check(request, _Ctx())

    assert metrics.counter_value(CHECK_DENIED) == 1
    assert metrics.counter_value(CHECK_ALLOWED) == 0
    assert metrics.observation_count(CHECK_LATENCY) == 1


@pytest.mark.asyncio
async def test_reporter_loop_flushes_on_its_interval(capsys):
    """The lifecycle loop flushes periodically and survives cancellation."""
    import asyncio

    from portunus.grpc.server import _metrics_reporter_loop

    metrics = _aggregator(counter_names=(CHECK_ALLOWED,))
    metrics.incr(CHECK_ALLOWED)
    task = asyncio.create_task(_metrics_reporter_loop(metrics, interval_seconds=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    docs = _read_emf_lines(capsys)
    assert docs, "reporter emitted nothing"
    assert sum(d[CHECK_ALLOWED] for d in docs) == 1


@pytest.mark.asyncio
async def test_audit_sources_report_queue_state(capsys):
    """The audit registration exposes queue depth/bytes and the stream gauge."""
    from portunus.grpc.server import register_audit_metrics
    from portunus.services.publish_queue import BoundedPublishQueue

    async def _noop_sender(stream: str, records: list) -> int:
        return 0

    queue = BoundedPublishQueue(maxsize=10, num_workers=1, batch_sender=_noop_sender)
    proc = SimpleNamespace(active_stream_count=3)
    metrics = _aggregator()
    register_audit_metrics(metrics, queue, proc, publish_service=None)  # type: ignore[arg-type]
    metrics.flush()

    doc = _read_emf_line(capsys)
    assert doc[ACTIVE_EXT_PROC_STREAMS] == 3
    assert doc[PUBLISHED_RECORDS] == 0
    assert doc[PUBLISH_QUEUE_BYTES] == 0
