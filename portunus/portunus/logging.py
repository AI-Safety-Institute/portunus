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

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from portunus.config import config
from portunus.services.xray_service import (
    XRayContext,
    get_trace_id,
    parse_trace_header,
)

logger = logging.getLogger("api.access")


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
    """Middleware that adds logging and set up x-ray context.

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

        # Extract and set trace ID from the request header
        aws_trace_header = request.headers.get("x-amzn-trace-id", "")
        trace_id, parent_id, sampled = parse_trace_header(aws_trace_header)
        app_title = request.app.title.replace(" ", "_").lower()

        # turn /log/<id> into just /log for segment name
        if len(request.url.path.split("/")) > 1:
            safe_path = request.url.path.split("/")[1]
        else:
            safe_path = ""

        segment_name = f"{app_title}/{safe_path}"

        if not trace_id:
            trace_id = "No-Trace-Id"
            sampled = False

        logger.info(
            f"Entering x-ray context: trace_id={trace_id}, "
            f"parent_id={parent_id}, sampled={sampled}, segment_name={segment_name}"
        )

        async with XRayContext(
            trace_id=trace_id,
            segment_name=segment_name,
            parent_id=parent_id,
            sampled=sampled,
        ):
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
