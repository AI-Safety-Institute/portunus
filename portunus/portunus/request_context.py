"""Per-request correlation ids shared by the gRPC servicers and logging.

Lives in its own module (not ``portunus.logging``) because importing that
module configures logging as a side effect, which the servicers must not
trigger — and not in a service module, because these are plain ContextVars
with no dependencies of their own.

Both ids are task-local under ``grpc.aio``: each RPC runs in its own task, so
concurrent requests cannot leak ids into each other's log lines.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional

# Envoy's ``x-request-id`` for the request/stream being served, set at each
# gRPC entry point (ext_authz Check, ext_proc stream init). Joins log lines to
# the Firehose audit records for the same request.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# The ``Root=`` component of an inbound ``x-amzn-trace-id``, when the ALB or
# Envoy supplied one. Purely for log correlation — nothing in Portunus emits
# spans.
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)


def parse_trace_root(header: str | None) -> Optional[str]:
    """Extract the ``Root=`` trace id from an ``X-Amzn-Trace-Id`` header.

    Args:
        header: The raw header value, or None/empty when absent.

    Returns:
        The root trace id, or None when the header is absent or carries no
        ``Root=`` component.
    """
    if not header:
        return None
    for component in header.split(";"):
        if component.startswith("Root="):
            return component[len("Root=") :] or None
    return None


def set_trace_id(trace_id: str) -> Token:
    """Set the trace id for the current task.

    Args:
        trace_id: The trace id to record on this task's log lines.

    Returns:
        The reset token for the context variable.
    """
    return trace_id_var.set(trace_id)


def get_trace_id() -> str:
    """Return the current trace id.

    Returns:
        The current trace id, or an empty string when unset. Callers must
        treat empty as "no trace" — never substitute a shared placeholder,
        which would collapse log correlation groups.
    """
    return trace_id_var.get() or ""
