"""In-process metric aggregation, flushed as one CloudWatch EMF line per interval.

Instrumentation points bump counters and histograms in memory (one asyncio
loop per process, so no locking); a reporter task flushes the interval to
stdout, where the ECS awslogs driver ships it and CloudWatch extracts the
``_aws`` directive into metrics. Dimensions are only ``ServiceName`` and
``Role`` to keep the custom-metric count independent of fleet size.
"""

from __future__ import annotations

import bisect
import json
import logging
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

logger = logging.getLogger("api.metrics")

CHECK_ALLOWED = "CheckAllowed"
# CheckShed (503) and CheckError (other 5xx) are subsets of CheckDenied.
CHECK_DENIED = "CheckDenied"
CHECK_SHED = "CheckShed"
CHECK_ERROR = "CheckError"
CHECK_LATENCY = "CheckLatency"
FULL_AUTH = "FullAuth"
FULL_AUTH_SHED = "FullAuthShed"
FULL_AUTH_LATENCY = "FullAuthLatency"
AUTH_REDIS_HIT = "AuthCacheRedisHit"
AUTH_REDIS_MISS = "AuthCacheRedisMiss"
AUTH_REDIS_ERROR = "AuthCacheRedisError"
DROPPED_RECORDS = "DroppedRecords"
DELIVERY_FAILED_RECORDS = "DeliveryFailedRecords"
KINESIS_THROTTLED_RECORDS = "KinesisThrottledRecords"
# Records in a PutRecords attempt that failed for any other reason: a
# non-throttling ErrorCode, an unconfirmable response, or the call raising.
KINESIS_PUT_ERRORS = "KinesisPutErrors"
PUBLISH_QUEUE_DEPTH = "PublishQueueDepth"
EVENT_LOOP_LAG = "EventLoopLag"

# Reported as 0 on a quiet interval, so a gap in a series means "no task".
AUTH_COUNTERS = (
    CHECK_ALLOWED,
    CHECK_DENIED,
    CHECK_SHED,
    CHECK_ERROR,
    FULL_AUTH,
    FULL_AUTH_SHED,
    AUTH_REDIS_HIT,
    AUTH_REDIS_MISS,
    AUTH_REDIS_ERROR,
)
AUDIT_COUNTERS = (
    DROPPED_RECORDS,
    DELIVERY_FAILED_RECORDS,
    KINESIS_THROTTLED_RECORDS,
    KINESIS_PUT_ERRORS,
)

_MILLISECONDS = {CHECK_LATENCY, FULL_AUTH_LATENCY, EVENT_LOOP_LAG}

# √2-spaced upper bounds, 0.5 ms to ~6 min (41 buckets, under EMF's 100-value
# limit). A sample is reported at its bucket's upper bound, so latency is never
# under-reported; samples past the last bound are clamped to it.
_BUCKET_BOUNDS = tuple(round(0.5 * (2 ** (i / 2)), 4) for i in range(41))


class MetricsAggregator:
    """Counters, gauges and latency histograms for one flush interval."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        namespace: str = "Portunus",
        service_name: str = "portunus",
        role: str = "all",
        counter_names: Iterable[str] = (),
    ) -> None:
        """Create an aggregator; disabled by default, which makes every call a no-op."""
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
        """Reconfigure in place (modules hold the singleton) and reset all state."""
        self.enabled = enabled
        self._namespace = namespace
        self._dimensions = {"ServiceName": service_name, "Role": role}
        self._counter_names = tuple(counter_names)
        self._counters: dict[str, int] = dict.fromkeys(self._counter_names, 0)
        self._histograms: dict[str, list[int]] = {}
        self._gauges: list[Callable[[], Mapping[str, float]]] = []

    def incr(self, name: str, amount: int = 1) -> None:
        """Add ``amount`` to a counter for this interval."""
        if self.enabled:
            self._counters[name] = self._counters.get(name, 0) + amount

    def observe(self, name: str, value: float) -> None:
        """Record one latency sample (milliseconds)."""
        if not self.enabled:
            return
        buckets = self._histograms.setdefault(name, [0] * len(_BUCKET_BOUNDS))
        index = min(bisect.bisect_left(_BUCKET_BOUNDS, value), len(_BUCKET_BOUNDS) - 1)
        buckets[index] += 1

    def register_gauge(self, source: Callable[[], Mapping[str, float]]) -> None:
        """Register a callback read at each flush."""
        self._gauges.append(source)

    def flush(self) -> None:
        """Emit the interval as one EMF line and reset it. Never raises."""
        if not self.enabled:
            return
        values: dict[str, Any] = dict(self._counters)
        self._counters = dict.fromkeys(self._counter_names, 0)
        for source in self._gauges:
            try:
                values.update(source())
            except Exception as e:
                logger.warning("Metric gauge raised: %s", type(e).__name__)
        for name, buckets in self._histograms.items():
            values[name] = {
                "Values": [b for b, n in zip(_BUCKET_BOUNDS, buckets) if n],
                "Counts": [float(n) for n in buckets if n],
            }
        self._histograms = {}
        if not values:
            return
        try:
            doc = {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": self._namespace,
                            "Dimensions": [list(self._dimensions)],
                            "Metrics": [
                                {
                                    "Name": name,
                                    "Unit": "Milliseconds"
                                    if name in _MILLISECONDS
                                    else "Count",
                                }
                                for name in values
                            ],
                        }
                    ],
                },
                **self._dimensions,
                **values,
            }
            # Straight to stdout: the structured log formatter would wrap and
            # bury the top-level ``_aws`` key.
            sys.stdout.write(json.dumps(doc) + "\n")
            sys.stdout.flush()
        except Exception as e:
            logger.warning("EMF metric emission failed: %s", type(e).__name__)


# Process-wide aggregator; disabled until configure_metrics() at gRPC start-up,
# so importing an instrumented module (tests, CLI, Glue) never writes to stdout.
metrics = MetricsAggregator()


def configure_metrics(
    *, enabled: bool, namespace: str, service_name: str, role: str
) -> MetricsAggregator:
    """Configure the singleton with the counters this role owns."""
    counters = (AUTH_COUNTERS if role in ("all", "auth") else ()) + (
        AUDIT_COUNTERS if role in ("all", "audit") else ()
    )
    metrics.configure(
        enabled=enabled,
        namespace=namespace,
        service_name=service_name,
        role=role,
        counter_names=counters,
    )
    return metrics
