"""The in-process EMF aggregator and the server's metrics reporter."""

from __future__ import annotations

import asyncio
import json

import pytest
from envoy.service.auth.v3 import attribute_context_pb2, external_auth_pb2

import portunus.config as portunus_config
from portunus.grpc.auth_servicer import PortunusAuthServicer
from portunus.metrics import (
    CHECK_ALLOWED,
    CHECK_DENIED,
    CHECK_LATENCY,
    DROPPED_RECORDS,
    PUBLISH_QUEUE_DEPTH,
    MetricsAggregator,
    configure_metrics,
)


def _aggregator(**kwargs) -> MetricsAggregator:
    defaults: dict = dict(
        enabled=True, namespace="Portunus", service_name="portunus-proxy", role="all"
    )
    defaults.update(kwargs)
    return MetricsAggregator(**defaults)


def _docs(capsys) -> list[dict]:
    """The EMF documents written to stdout.

    Only lines that parse as an EMF document count: a logging handler
    installed on stdout earlier in the session (``portunus.logging`` or a
    test dependency) can interleave warning lines, such as the one a failing
    gauge produces.
    """
    docs = []
    for line in capsys.readouterr().out.splitlines():
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "_aws" in parsed:
            docs.append(parsed)
    return docs


def test_flush_emits_a_valid_emf_document(capsys):
    metrics = _aggregator()
    metrics.incr(CHECK_ALLOWED)
    metrics.observe(CHECK_LATENCY, 3.0)
    metrics.flush()

    (doc,) = _docs(capsys)
    directive = doc["_aws"]["CloudWatchMetrics"][0]
    assert isinstance(doc["_aws"]["Timestamp"], int)
    assert directive["Namespace"] == "Portunus"
    assert directive["Dimensions"] == [["ServiceName", "Role"]]
    assert (doc["ServiceName"], doc["Role"]) == ("portunus-proxy", "all")
    units = {m["Name"]: m["Unit"] for m in directive["Metrics"]}
    assert units == {CHECK_ALLOWED: "Count", CHECK_LATENCY: "Milliseconds"}
    assert doc[CHECK_ALLOWED] == 1


def test_disabled_aggregator_is_a_no_op(capsys):
    metrics = _aggregator(enabled=False)
    metrics.incr(CHECK_ALLOWED)
    metrics.observe(CHECK_LATENCY, 1.0)
    metrics.register_gauge(lambda: {PUBLISH_QUEUE_DEPTH: 1})
    metrics.flush()
    assert capsys.readouterr().out == ""


def test_counts_are_per_interval_and_registered_counters_report_zero(capsys):
    metrics = _aggregator(counter_names=(CHECK_ALLOWED, CHECK_DENIED))
    metrics.incr(CHECK_ALLOWED, 2)
    metrics.flush()
    metrics.incr(CHECK_DENIED)
    metrics.flush()

    first, second = _docs(capsys)
    assert (first[CHECK_ALLOWED], first[CHECK_DENIED]) == (2, 0)
    assert (second[CHECK_ALLOWED], second[CHECK_DENIED]) == (0, 1)


def test_histogram_reports_bucket_upper_bounds_and_resets(capsys):
    metrics = _aggregator()
    for value in (0.4, 0.5, 0.6, 1e9):
        metrics.observe(CHECK_LATENCY, value)
    metrics.flush()
    metrics.flush()

    (doc,) = _docs(capsys)  # the second, empty interval emits nothing
    hist = doc[CHECK_LATENCY]
    assert hist["Values"][:2] == [0.5, 0.7071]
    assert hist["Counts"][:2] == [2.0, 1.0]
    assert hist["Counts"][-1] == 1.0  # the huge sample lands in the last bucket
    assert hist["Values"][-1] == pytest.approx(0.5 * 2**20)


def test_gauges_are_read_at_flush_and_a_failing_one_does_not_raise(capsys):
    metrics = _aggregator()
    depth = {"value": 3}
    metrics.register_gauge(lambda: {PUBLISH_QUEUE_DEPTH: depth["value"]})
    metrics.register_gauge(lambda: 1 / 0)  # type: ignore[arg-type, return-value]
    metrics.incr(DROPPED_RECORDS)
    depth["value"] = 5
    metrics.flush()

    (doc,) = _docs(capsys)
    assert doc[PUBLISH_QUEUE_DEPTH] == 5
    assert doc[DROPPED_RECORDS] == 1


def test_emission_failure_does_not_raise(monkeypatch):
    metrics = _aggregator()
    metrics.incr(CHECK_ALLOWED)

    def broken_dumps(*_args, **_kwargs):
        raise TypeError("boom")

    monkeypatch.setattr("portunus.metrics.json.dumps", broken_dumps)
    metrics.flush()  # must not raise


def test_roles_preregister_only_their_own_counters(capsys):
    try:
        for role in ("auth", "audit"):
            configure_metrics(enabled=True, namespace="P", service_name="p", role=role)
            from portunus.metrics import metrics

            metrics.flush()
        auth, audit = _docs(capsys)
        assert CHECK_ALLOWED in auth and DROPPED_RECORDS not in auth
        assert DROPPED_RECORDS in audit and CHECK_ALLOWED not in audit
    finally:
        configure_metrics(enabled=False, namespace="P", service_name="p", role="all")


@pytest.mark.asyncio
async def test_check_records_outcome_and_latency(monkeypatch, capsys):
    import portunus.grpc.auth_servicer as auth_servicer_mod

    metrics = _aggregator(counter_names=(CHECK_ALLOWED, CHECK_DENIED))
    monkeypatch.setattr(auth_servicer_mod, "metrics", metrics)
    monkeypatch.setattr(portunus_config.config.grpc, "proxy_api_key", "")
    servicer = PortunusAuthServicer(auth_service=None)  # type: ignore[arg-type]
    request = external_auth_pb2.CheckRequest(
        attributes=attribute_context_pb2.AttributeContext(
            request=attribute_context_pb2.AttributeContext.Request(
                http=attribute_context_pb2.AttributeContext.HttpRequest(id="req-m")
            )
        )
    )

    class _Ctx:
        def invocation_metadata(self):
            return []

    await servicer.Check(request, _Ctx())  # no credential: denied
    metrics.flush()

    (doc,) = _docs(capsys)
    assert (doc[CHECK_ALLOWED], doc[CHECK_DENIED]) == (0, 1)
    assert sum(doc[CHECK_LATENCY]["Counts"]) == 1


@pytest.mark.asyncio
async def test_reporter_loop_flushes_on_its_interval(capsys):
    from portunus.grpc.server import _metrics_reporter_loop

    metrics = _aggregator(counter_names=(CHECK_ALLOWED,))
    metrics.incr(CHECK_ALLOWED)
    task = asyncio.create_task(_metrics_reporter_loop(metrics, interval_seconds=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    docs = _docs(capsys)
    assert docs
    assert sum(d[CHECK_ALLOWED] for d in docs) == 1


@pytest.mark.asyncio
async def test_queue_drops_are_counted_at_the_event(monkeypatch, capsys):
    import portunus.services.publish_queue as publish_queue_mod
    from portunus.services.publish_queue import BoundedPublishQueue, PublishTask

    metrics = _aggregator()
    monkeypatch.setattr(publish_queue_mod, "metrics", metrics)

    async def _send(stream: str, records: list) -> int:
        return 0

    queue = BoundedPublishQueue(maxsize=1, num_workers=0, batch_sender=_send)
    task = PublishTask(build=lambda: ("audit", b"x"), label="body")
    assert queue.submit_droppable(task)
    assert not queue.submit_droppable(task)
    metrics.flush()

    (doc,) = _docs(capsys)
    assert doc[DROPPED_RECORDS] == 1 == queue.dropped_total
