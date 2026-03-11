"""
X-Ray tracing service module.

This module provides a service for AWS X-Ray distributed tracing functionality,
including trace context extraction, segment management, and logging integration.
"""

import logging
from contextvars import ContextVar, Token
from typing import Optional, Tuple

from aws_xray_sdk.core import patch_all, xray_recorder
from aws_xray_sdk.core.async_context import AsyncContext

from portunus.config import config

# Context variable for trace ID
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)


class XRayContext:
    """Context manager for setting and resetting trace ID in context vars."""

    def __init__(
        self,
        trace_id: str,
        segment_name: Optional[str] = None,
        parent_id: Optional[str] = None,
        sampled: Optional[bool] = None,
    ):
        self.trace_id = trace_id
        self.segment_name = segment_name
        self.parent_id = parent_id
        self.sampled = sampled
        self.token = None
        self.xray_segment = None

    # Sync context management
    def __enter__(self):
        raise TypeError("Use 'async with' instead of 'with' for this context manager")

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    async def __aenter__(self):
        self.token = set_trace_id(self.trace_id)

        # Enter the nested async context manager
        self.xray_segment = await xray_recorder.in_segment_async(  # type: ignore[unresolved-attribute]  # missing from stubs
            name=self.segment_name,
            traceid=self.trace_id,
            parent_id=self.parent_id,
            sampling=self.sampled if self.sampled is not None else True,
        ).__aenter__()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # First check if there's an exception
        if exc_type is not None and self.xray_segment is not None:
            import traceback

            # Add exception to the segment
            self.xray_segment.add_exception(
                exception=exc_val, stack=traceback.extract_tb(exc_tb), remote=False
            )
        # First exit the nested context manager
        # We need to tell the xray_recorder to end the current segment
        if self.xray_segment is not None:
            # The segment is automatically ended when exiting the context manager
            # We don't need to explicitly close it
            xray_recorder.end_segment()

        # Then reset our token
        if self.token:
            trace_id_var.reset(self.token)


class XRayTraceFormatter(logging.Formatter):
    """Formatter that adds X-Ray trace ID to log records."""

    def format(self, record):
        trace_id = None

        try:
            segment = xray_recorder.current_segment()
            if segment and segment.trace_id:
                trace_id = segment.trace_id
        except Exception:
            trace_id = None

        if not trace_id:
            trace_id = get_trace_id()

        record.trace = trace_id or "no-trace"
        return super().format(record)


def parse_trace_header(
    header: str,
) -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    """
    Parse the X-Amzn-Trace-Id header and extract components.

    Args:
        header: The X-Amzn-Trace-Id header value

    Returns:
        Tuple containing:
            - trace_id: The X-Ray trace ID
            - parent_id: The parent segment ID
            - sampled: Boolean indicating if this request is sampled
    """
    if not header:
        return None, None, None

    trace_id = None
    parent_id = None
    sampled = None

    components = header.split(";")
    for component in components:
        if component.startswith("Root="):
            trace_id = component[5:]  # Extract value after "Root="
        elif component.startswith("Parent="):
            parent_id = component[7:]  # Extract value after "Parent="
        elif component.startswith("Sampled="):
            sampled = component[8:] == "1"  # Convert to boolean

    return trace_id, parent_id, sampled


def get_trace_id() -> str:
    """Get the current trace ID from context.

    Returns:
        str: The current trace ID or an empty string if not set
    """
    return trace_id_var.get() or "No-Trace-Id"


def set_trace_id(trace_id: str) -> Token:
    """Set the trace ID in the context.

    Args:
        trace_id (str): The trace ID to set
    """
    return trace_id_var.set(trace_id)


class XRayService:
    """
    Service for AWS X-Ray distributed tracing functionality.

    This service manages X-Ray configuration, trace context extraction,
    segment management, and integration with logging.
    """

    def __init__(self):
        """Initialize the X-Ray service and configure X-Ray SDK."""
        self._configure_xray()
        self.recorder = xray_recorder

    def _configure_xray(self):
        """Configure X-Ray SDK with application settings."""
        # Patch all supported libraries for X-Ray tracing
        patch_all()

        # Configure X-Ray recorder
        xray_recorder.configure(
            service="portunus",
            context=AsyncContext(),
            daemon_address=config.aws.xray_daemon_address,
            sampling=True,
        )

        # Set up X-Ray log groups
        # See https://github.com/aws/aws-xray-sdk-python/issues/188#issuecomment-728222591
        log_resources = xray_recorder._aws_metadata.setdefault("cloudwatch_logs", [{}])  # type: ignore[unresolved-attribute]  # private attr not in stubs
        log_resources[0]["log_group"] = config.aws.xray_log_group

        # Set extra log groups if configured
        if config.aws.xray_extra_log_groups:
            for group in config.aws.xray_extra_log_groups.split(","):
                if group.strip():
                    log_resources.append({"log_group": group.strip()})
