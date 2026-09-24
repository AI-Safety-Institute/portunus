"""In-process metric aggregation, flushed as CloudWatch EMF.

Portunus serves up to a few thousand requests per second per task, so it
never emits one metric document per request. Instrumentation points bump
in-memory counters and histograms (O(1), lock-free — one asyncio loop per
process, so nothing here is ever entered concurrently), and a background
reporter flushes the accumulated interval as a single Embedded Metric Format
JSON line on stdout every ``METRICS_FLUSH_INTERVAL_SECONDS``.

EMF goes to stdout because that is where the ECS ``awslogs`` driver already
reads: CloudWatch Logs extracts any line carrying a top-level ``_aws``
directive into metrics on its own. No agent, no SDK dependency, and no
per-metric infra ``MetricFilter``.

Three kinds of series:

* **Counters** — bumped by the hot path, reported as the interval delta and
  reset at flush, so a CloudWatch ``Sum`` over any period is that period's
  true count regardless of task restarts. Counters named at configuration
  time are reported even when zero, so a gap in the series means "task
  gone" rather than "nothing happened".
* **Delta sources** — components that already keep their own cumulative
  counters (the publish queue, the L1 auth cache) register a snapshot
  callable; the reporter differences successive snapshots.
* **Gauges** — point-in-time callables sampled at flush (queue depth, active
  streams).

Distributions (latencies, event-loop lag) accumulate into a fixed √2-spaced
bucket ladder and are emitted as EMF ``Values``/``Counts`` arrays. CloudWatch
derives Min/Max/Average/Sum/percentiles from those, so one ``CheckLatency``
metric answers "p99 auth latency" without an EMF line per request. Each
bucket reports its **upper bound**, so a latency is never under-reported
(over-reported by at most √2 ≈ 41%). The ladder is 41 buckets — comfortably
inside the EMF ceiling of 100 distinct values per metric.

Dimensions are deliberately low cardinality: ``ServiceName`` and ``Role``
only. No per-task, per-principal or per-host dimension — those multiply the
custom-metric bill by the size of the fleet and of the customer base.
"""

from __future__ import annotations

import bisect
import json
import logging
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("api.metrics")

# --- Metric names ---------------------------------------------------------
#
# Constants rather than string literals at the call sites: a typo'd metric
# name is invisible in production (the series simply never appears).

# ext_authz outcomes. ``CheckShed`` (503) and ``CheckError`` (5xx) are
# SUBSETS of ``CheckDenied`` — allowed/denied still partition every Check.
CHECK_ALLOWED = "CheckAllowed"
CHECK_DENIED = "CheckDenied"
CHECK_SHED = "CheckShed"
CHECK_ERROR = "CheckError"
CHECK_LATENCY = "CheckLatency"

# L1 (in-process) auth cache — reported from LocalAuthCache's own counters.
AUTH_L1_HIT = "AuthCacheL1Hit"
AUTH_L1_STALE_SERVED = "AuthCacheL1StaleServed"
AUTH_L1_MISS = "AuthCacheL1Miss"
AUTH_L1_COALESCED = "AuthCacheL1Coalesced"

# L2 (Redis) auth cache, counted on the auth path.
AUTH_REDIS_HIT = "AuthCacheRedisHit"
AUTH_REDIS_MISS = "AuthCacheRedisMiss"
AUTH_REDIS_ERROR = "AuthCacheRedisError"

# Full authentication: STS get-caller-identity + Secrets Manager fetch.
FULL_AUTH = "FullAuth"
FULL_AUTH_SHED = "FullAuthShed"
FULL_AUTH_LATENCY = "FullAuthLatency"

# Audit pipeline — delta sources on BoundedPublishQueue / PublishService.
SUBMITTED_RECORDS = "SubmittedRecords"
PUBLISHED_RECORDS = "PublishedRecords"
DROPPED_RECORDS = "DroppedRecords"
BUILD_FAILED_RECORDS = "BuildFailedRecords"
DELIVERY_FAILED_RECORDS = "DeliveryFailedRecords"
SKIPPED_UNCONFIGURED_RECORDS = "SkippedUnconfiguredRecords"
SENTINEL_DROPPED_RECORDS = "SentinelDroppedRecords"
FIREHOSE_THROTTLED_RECORDS = "FirehoseThrottledRecords"
FIREHOSE_PUT_ERRORS = "FirehosePutErrors"
PUBLISH_QUEUE_DEPTH = "PublishQueueDepth"
PUBLISH_QUEUE_BYTES = "PublishQueueBytes"
ACTIVE_EXT_PROC_STREAMS = "ActiveExtProcStreams"

# Process health.
EVENT_LOOP_LAG = "EventLoopLag"

#: Counters an ext_authz process owns, pre-registered so they report zero on
#: a quiet interval. The audit counters all arrive via delta sources, which
#: report every interval anyway, so they need no equivalent list.
AUTH_COUNTERS: tuple[str, ...] = (
    CHECK_ALLOWED,
    CHECK_DENIED,
    CHECK_SHED,
    CHECK_ERROR,
    AUTH_REDIS_HIT,
    AUTH_REDIS_MISS,
    AUTH_REDIS_ERROR,
    FULL_AUTH,
    FULL_AUTH_SHED,
)

#: CloudWatch unit per metric; anything unlisted is a ``Count``.
_UNITS: Dict[str, str] = {
    CHECK_LATENCY: "Milliseconds",
    FULL_AUTH_LATENCY: "Milliseconds",
    EVENT_LOOP_LAG: "Milliseconds",
    PUBLISH_QUEUE_BYTES: "Bytes",
}

# √2-spaced bucket upper bounds, 0.5 ms → ~6 minutes (41 entries). Samples
# above the last bound land in the final bucket and are reported at that
# bound, so an extreme outlier is counted but its magnitude is clamped.
_BUCKET_BOUNDS: tuple[float, ...] = tuple(
    round(0.5 * (2 ** (i / 2)), 4) for i in range(41)
)
_NUM_BUCKETS = len(_BUCKET_BOUNDS)


class _CurrentStdoutHandler(logging.Handler):
    """Write to the *current* ``sys.stdout``, resolved per emit.

    Late binding (vs ``StreamHandler(sys.stdout)``) so stdout replacement —
    pytest capture, in particular — sees the EMF lines.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(self.format(record) + "\n")
        except Exception:  # pragma: no cover — mirror StreamHandler behaviour
            self.handleError(record)


# propagate=False: EMF lines must reach stdout verbatim, not wrapped by the
# root logger's structured formatter (which would bury ``_aws``).
_emf_logger = logging.getLogger("portunus.emf")
_emf_logger.propagate = False
_emf_logger.setLevel(logging.INFO)
if not _emf_logger.handlers:
    _handler = _CurrentStdoutHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _emf_logger.addHandler(_handler)


_MetricValue = Union[int, float, Dict[str, List[float]]]


def emit_emf(
    values: Mapping[str, _MetricValue],
    *,
    namespace: str,
    dimensions: Mapping[str, str],
    units: Optional[Mapping[str, str]] = None,
) -> None:
    """Write one EMF document to stdout.

    Args:
        values: Metric name → scalar, or a
            ``{"Values": [...], "Counts": [...]}`` distribution.
        namespace: CloudWatch namespace.
        dimensions: Dimension name → value. One dimension set is declared,
            over exactly these keys.
        units: Optional metric name → CloudWatch unit (default ``Count``).
    """
    if not values:
        return
    units = units or {}
    doc: Dict[str, Any] = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": namespace,
                    "Dimensions": [list(dimensions)],
                    "Metrics": [
                        {"Name": name, "Unit": units.get(name, "Count")}
                        for name in values
                    ],
                }
            ],
        },
        **dimensions,
        **values,
    }
    _emf_logger.info(json.dumps(doc))


class MetricsAggregator:
    """Accumulates counters and distributions; flushes them as one EMF line.

    Not thread-safe by design: Portunus runs a single asyncio loop per
    process and every instrumentation point is synchronous, so the hot path
    needs no lock.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        namespace: str = "Portunus",
        service_name: str = "portunus",
        role: str = "all",
        counter_names: Iterable[str] = (),
    ) -> None:
        """Initialise an aggregator.

        Args:
            enabled: When False every method is a no-op and nothing is ever
                written to stdout (the default, so local runs and tests stay
                quiet).
            namespace: CloudWatch namespace for the emitted metrics.
            service_name: Value of the ``ServiceName`` dimension.
            role: Value of the ``Role`` dimension (``all``/``auth``/``audit``).
            counter_names: Counters to report even when zero for an interval.
        """
        self.configure(
            enabled=enabled,
            namespace=namespace,
            service_name=service_name,
            role=role,
            counter_names=counter_names,
        )

    def configure(
        self,
        *,
        enabled: bool,
        namespace: str,
        service_name: str,
        role: str,
        counter_names: Iterable[str] = (),
    ) -> None:
        """(Re)configure in place and drop any accumulated state.

        Mutates rather than replacing the instance so the module-level
        ``metrics`` singleton the instrumented modules imported at start-up
        stays the live object.

        Args:
            enabled: Whether to record and emit at all.
            namespace: CloudWatch namespace for the emitted metrics.
            service_name: Value of the ``ServiceName`` dimension.
            role: Value of the ``Role`` dimension.
            counter_names: Counters to report even when zero for an interval.
        """
        self._enabled = enabled
        self._namespace = namespace
        self._dimensions = {"ServiceName": service_name, "Role": role}
        self._counter_names = tuple(counter_names)
        self._counters: Dict[str, int] = {name: 0 for name in self._counter_names}
        self._histograms: Dict[str, List[int]] = {}
        self._delta_sources: List[Callable[[], Mapping[str, int]]] = []
        self._gauge_sources: List[Callable[[], Mapping[str, float]]] = []
        self._last_snapshot: Dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        """Whether this aggregator records and emits anything."""
        return self._enabled

    # --- hot path ---------------------------------------------------------

    def incr(self, name: str, amount: int = 1) -> None:
        """Add ``amount`` to the counter ``name`` for this interval.

        Args:
            name: Metric name, ideally one of this module's constants.
            amount: Increment (default 1).
        """
        if not self._enabled:
            return
        self._counters[name] = self._counters.get(name, 0) + amount

    def observe(self, name: str, value: float) -> None:
        """Record one sample of the distribution ``name``.

        Args:
            name: Metric name, ideally one of this module's constants.
            value: The sample in the metric's unit (milliseconds for the
                latency metrics). Bucketed on a √2 ladder; the bucket's
                upper bound is what reaches CloudWatch.
        """
        if not self._enabled:
            return
        buckets = self._histograms.get(name)
        if buckets is None:
            buckets = self._histograms[name] = [0] * _NUM_BUCKETS
        index = bisect.bisect_left(_BUCKET_BOUNDS, value)
        if index >= _NUM_BUCKETS:
            index = _NUM_BUCKETS - 1
        buckets[index] += 1

    # --- registration -----------------------------------------------------

    def register_delta_source(self, source: Callable[[], Mapping[str, int]]) -> None:
        """Register a callable returning cumulative counters to difference.

        The current values are taken as the baseline immediately, so the
        first flush after registration reports the interval since start-up
        rather than the process's lifetime totals.

        Args:
            source: Returns metric name → cumulative count.
        """
        self._delta_sources.append(source)
        if self._enabled:
            self._last_snapshot.update(self._read(source))

    def register_gauge_source(self, source: Callable[[], Mapping[str, float]]) -> None:
        """Register a callable sampled at each flush.

        Args:
            source: Returns metric name → point-in-time value.
        """
        self._gauge_sources.append(source)

    # --- introspection (tests, assertions) --------------------------------

    def counter_value(self, name: str) -> int:
        """Return the counter's value so far this interval.

        Args:
            name: Metric name.

        Returns:
            The accumulated count; 0 when never incremented.
        """
        return self._counters.get(name, 0)

    def observation_count(self, name: str) -> int:
        """Return how many samples the distribution holds this interval.

        Args:
            name: Metric name.

        Returns:
            The sample count; 0 when never observed.
        """
        return sum(self._histograms.get(name, ()))

    # --- flush ------------------------------------------------------------

    def flush(self) -> None:
        """Emit the interval as one EMF document and reset the accumulators.

        Never raises: a metrics failure must not take down the process it is
        measuring, nor blind the metrics that did collect — a source that
        raises is logged and skipped while the rest still ship.
        """
        if not self._enabled:
            return
        values: Dict[str, _MetricValue] = {}

        for source in self._delta_sources:
            current = self._read(source)
            for name, total in current.items():
                values[name] = total - self._last_snapshot.get(name, total)
            self._last_snapshot.update(current)

        values.update(self._counters)
        self._counters = {name: 0 for name in self._counter_names}

        for gauge_source in self._gauge_sources:
            values.update(self._read(gauge_source))

        for name, buckets in self._histograms.items():
            bucket_values = [
                _BUCKET_BOUNDS[i] for i, count in enumerate(buckets) if count
            ]
            if bucket_values:
                values[name] = {
                    "Values": bucket_values,
                    "Counts": [float(count) for count in buckets if count],
                }
        self._histograms.clear()

        try:
            emit_emf(
                values,
                namespace=self._namespace,
                dimensions=self._dimensions,
                units=_UNITS,
            )
        except Exception as e:
            logger.warning("EMF metric emission failed: %s", type(e).__name__)

    @staticmethod
    def _read(source: Callable[[], Mapping[str, Any]]) -> Dict[str, Any]:
        try:
            return dict(source())
        except Exception as e:
            logger.warning("Metric source raised: %s", type(e).__name__)
            return {}


#: Process-wide aggregator, imported by the instrumented modules. Disabled
#: until :func:`configure_metrics` turns it on at gRPC start-up, so importing
#: an instrumented module (in a test, the CLI, or the Glue job) never writes
#: to stdout.
metrics = MetricsAggregator()


def configure_metrics(
    *,
    enabled: bool,
    namespace: str,
    service_name: str,
    role: str,
) -> MetricsAggregator:
    """Configure the process-wide aggregator and return it.

    Args:
        enabled: Whether to record and emit at all.
        namespace: CloudWatch namespace.
        service_name: ``ServiceName`` dimension value.
        role: ``Role`` dimension value (``all``/``auth``/``audit``).

    Returns:
        The process-wide aggregator (also reachable as
        ``portunus.metrics.metrics``).
    """
    metrics.configure(
        enabled=enabled,
        namespace=namespace,
        service_name=service_name,
        role=role,
        counter_names=AUTH_COUNTERS if role in ("all", "auth") else (),
    )
    return metrics
