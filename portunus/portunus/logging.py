"""
Logging module for the Portunus.

This module centralizes all logging functionality for the Portunus service.
It configures structured logging with consistent formatting, correlation IDs,
and contextual information across all log messages.
"""

import json
import logging
import sys

from portunus.config import config
from portunus.services.xray_service import request_id_var, trace_id_var

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

        # Correlation ids, omitted (not placeholder-filled) when unset so
        # their absence is queryable. request_id joins log lines to Firehose
        # audit records; trace_id joins them to X-Ray traces.
        request_id = request_id_var.get()
        if request_id and "request_id" not in record.__dict__:
            log_data["request_id"] = request_id
        trace_id = trace_id_var.get()
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
