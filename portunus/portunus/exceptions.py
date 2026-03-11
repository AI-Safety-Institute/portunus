"""
Exceptions for the Portunus.

This module defines a hierarchy of exceptions used throughout the Portunus
application. The hierarchy is designed to provide clear categorization of different
error types and to enable specific error handling based on exception categories.
"""

from dataclasses import dataclass


class PortunusError(Exception):
    """Base exception for all Portunus errors."""

    def __init__(self, message: str = "An error occurred in the Portunus"):
        self.message = message
        super().__init__(self.message)


# Authentication Errors


class AuthenticationError(PortunusError):
    """Base class for authentication-related errors."""

    def __init__(self, message: str = "Authentication error"):
        super().__init__(message)


@dataclass
class CredentialsError(AuthenticationError):
    """Exception raised when credentials are missing, invalid, or expired."""

    message: str = "Missing or invalid AWS credentials"


@dataclass
class PayloadError(AuthenticationError):
    """Exception raised when a payload cannot be properly decoded or processed.

    Attributes:
        message (str): The error message describing what went wrong
    """

    message: str


class AuthError(AuthenticationError):
    """Exception raised for general authentication issues."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


# Service Errors


class ServiceError(PortunusError):
    """Base class for service-related errors."""

    def __init__(self, message: str = "Service error"):
        super().__init__(message)


@dataclass
class FetchSecretError(ServiceError):
    """Exception raised when there's an error retrieving a secret.

    Attributes:
        http_status_code (int): HTTP status code to return
        message (str): Error message describing the issue
    """

    http_status_code: int
    message: str


class ConfigurationError(ServiceError):
    """Exception raised when there's an error in the configuration."""

    def __init__(self, message: str = "Configuration error"):
        super().__init__(message)


# State Management Errors


class StateError(PortunusError):
    """Base class for state management errors."""

    def __init__(self, message: str = "State management error"):
        super().__init__(message)


class RedisError(StateError):
    """Exception raised when there's an error with Redis operations."""

    def __init__(self, message: str = "Redis operation failed"):
        super().__init__(message)


class CacheError(StateError):
    """Exception raised when there's an error with caching operations."""

    def __init__(self, message: str = "Cache operation failed"):
        super().__init__(message)


class LoggingError(StateError):
    """Exception raised when there's an error with logging operations."""

    def __init__(self, message: str = "Logging operation failed"):
        super().__init__(message)


class LogDecodeError(LoggingError):
    """Exception raised when log decoding fails."""

    def __init__(
        self, message: str = "Log decode operation failed", field: str | None = None
    ):
        if field:
            message = f"Failed to decode {field}: {message}"
        super().__init__(message)
        self.field = field


class LogNotFoundError(LoggingError):
    """Exception raised when log lookup fails."""

    def __init__(
        self, message: str = "Failed to retrieve log", message_id: str | None = None
    ):
        if message_id:
            message = f"Log with message_id {message_id} not found"
        super().__init__(message)


# Validation Errors


class ValidationError(PortunusError):
    """Base class for validation errors."""

    def __init__(self, message: str = "Validation error"):
        super().__init__(message)


@dataclass
class InputValidationError(ValidationError):
    """Exception raised when input validation fails.

    Attributes:
        field (str): The name of the field that failed validation
        message (str): Error message describing the issue
    """

    field: str
    message: str

    def __post_init__(self):
        self.message = f"Validation error for field '{self.field}': {self.message}"
