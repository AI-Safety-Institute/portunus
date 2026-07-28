"""CloudWatch EMF metric emission.

Emits Embedded Metric Format JSON lines on a dedicated stdout logger,
bypassing ``StructuredLogFormatter`` — EMF requires the ``_aws`` key at the
top level of the line. CloudWatch Logs extracts the metrics automatically,
so no agent, SDK dependency, or per-metric infra MetricFilter is needed.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Dict, Mapping, Optional, Union

NAMESPACE = "portunus-proxy"


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


def emit_metrics(
    metrics: Mapping[str, Union[int, float]],
    *,
    units: Optional[Dict[str, str]] = None,
    namespace: str = NAMESPACE,
) -> None:
    """Emit one EMF document carrying ``metrics`` (no dimensions, fleet-wide).

    Args:
        metrics: Metric name → value. Names should be CamelCase.
        units: Optional metric name → CloudWatch unit (default ``Count``).
        namespace: CloudWatch namespace.
    """
    if not metrics:
        return
    units = units or {}
    doc: Dict[str, object] = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": namespace,
                    "Dimensions": [[]],
                    "Metrics": [
                        {"Name": name, "Unit": units.get(name, "Count")}
                        for name in metrics
                    ],
                }
            ],
        },
        **metrics,
    }
    _emf_logger.info(json.dumps(doc))
