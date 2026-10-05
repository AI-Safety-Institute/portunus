"""
Logging module for the Portunus.

This module centralizes all logging functionality for the Portunus service.
It configures structured logging with consistent formatting, correlation IDs,
and contextual information across all log messages.
"""

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar, Token
from typing import Optional, Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from portunus.config import config

logger = logging.getLogger("api.access")

# The correlation id of the request being served, set by ``LoggingMiddleware``:
# the ``Root=`` id of the inbound ``X-Amzn-Trace-Id`` header when there is one,
# otherwise a fresh uuid4. ``/authorise`` returns it as the ``request_id`` that
# ties every audit record for the proxied request together, so it must be
# unique per request.
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)


def parse_trace_header(
    header: str,
) -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    """
    Parse the X-Amzn-Trace-Id header and extract components.

    Args:
        header: The X-Amzn-Trace-Id header value

    Returns:
        Tuple containing:
            - trace_id: The trace ID
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
        str: The current trace ID, or "No-Trace-Id" if not set
    """
    return trace_id_var.get() or "No-Trace-Id"


def set_trace_id(trace_id: str) -> Token:
    """Set the trace ID in the context.

    Args:
        trace_id (str): The trace ID to set
    """
    return trace_id_var.set(trace_id)


class StructuredLogFormatter(logging.Formatter):
    """Formatter that outputs logs as structured JSON.

    This formatter includes the trace ID, request ID, and principal ID
    from the context variables, as well as timestamp, log level, and
    any other contextual information provided in the log record.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a JSON string.

        Args:
            record: The log record to format

        Returns:
            str: The formatted log message as a JSON string
        """
        # Start with basic log record information
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        # Add trace ID from context if available
        trace_id = get_trace_id()
        if trace_id:
            log_data["trace_id"] = trace_id

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra attributes from the log record
        for key, value in record.__dict__.items():
            if key not in {
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "id",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
            }:
                log_data[key] = value

        return json.dumps(log_data)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that adds logging and sets the trace ID context.

    This middleware captures request information, sets context variables,
    and logs request and response details with performance metrics.
    """

    def __init__(self, app: ASGIApp):
        """Initialize the middleware.

        Args:
            app: The ASGI application
        """
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        """Process the request and log details.

        Args:
            request: The incoming request
            call_next: The next middleware or route handler

        Returns:
            The response from the next middleware or route handler
        """
        start_time = time.time()

        # Correlate on the caller's trace id when it sent one, else mint one.
        # Nothing upstream supplies a trace id any more (the Envoy X-Ray tracer
        # used to), and a shared placeholder would collapse every request's
        # audit records onto one request_id.
        aws_trace_header = request.headers.get("x-amzn-trace-id", "")
        trace_id, parent_id, sampled = parse_trace_header(aws_trace_header)

        if not trace_id:
            trace_id = str(uuid.uuid4())
            sampled = False

        logger.info(
            f"Request trace context: trace_id={trace_id}, "
            f"parent_id={parent_id}, sampled={sampled}"
        )

        token = set_trace_id(trace_id)
        try:
            # Get client IP
            if "x-forwarded-for" in request.headers:
                client_ip = request.headers["x-forwarded-for"].split(",")[0]
            else:
                client_ip = request.client.host if request.client else "unknown"

            # Add standard request metadata to the context
            request_metadata = {
                "client_ip": client_ip,
                "method": request.method,
                "path": request.url.path,
                "user_agent": request.headers.get("user-agent", "-"),
            }

            # Process the request and get the response
            try:
                # Log the incoming request
                logger.info(
                    f"Request started: {request.method} {request.url.path}",
                    extra=request_metadata,
                )

                # Call the next middleware or route handler
                response = await call_next(request)

                # Calculate processing time
                process_time = time.time() - start_time

                # Add response metadata
                response_metadata = {
                    **request_metadata,
                    "status_code": response.status_code,
                    "process_time": f"{process_time:.4f}s",
                }

                # Log the completed request
                logger.info(
                    f"Request completed: {request.method} {request.url.path} "
                    f"{response.status_code} {process_time:.4f}s",
                    extra=response_metadata,
                )

                return response

            except Exception as e:
                # Calculate processing time
                process_time = time.time() - start_time

                # Add error metadata
                error_metadata = {
                    **request_metadata,
                    "error": str(e),
                    "process_time": f"{process_time:.4f}s",
                }

                # Log the error
                logger.error(
                    f"Request error: {request.method} {request.url.path} "
                    f"Error: {str(e)} {process_time:.4f}s",
                    extra=error_metadata,
                    exc_info=True,
                )
                raise
        finally:
            trace_id_var.reset(token)


def configure_logging():
    """Configure logging for the application.

    This function sets up the root logger and all application loggers
    with appropriate handlers, formatters, and log levels based on
    the application configuration.
    """
    # Set the log level from configuration
    log_level = getattr(logging, config.log_level)

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any existing handlers
    if root_logger.handlers:
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)

    # Create console handler with structured formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Use structured JSON formatter in production
    formatter = StructuredLogFormatter()
    console_handler.setFormatter(formatter)

    # Add handler to root logger
    root_logger.addHandler(console_handler)

    # Configure app-specific logger
    app_logger = logging.getLogger("api")
    app_logger.setLevel(log_level)
    app_logger.propagate = True

    logger.info(f"Logging configured with level {config.log_level}")


# Initialize logging when module is imported
configure_logging()
