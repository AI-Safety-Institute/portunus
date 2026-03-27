"""
Configuration module for the Portunus.

This module centralizes all configuration options for the Portunus service.
It loads configuration from environment variables with reasonable defaults and
provides validation and documentation for all options.
"""

import logging
import os
from functools import lru_cache
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)


class RedisConfig(BaseModel):
    """Redis configuration settings.

    Attributes:
        host: Redis server hostname
        port: Redis server port
        password: Redis server password (optional)
        cache_duration: How long to cache authorization responses (seconds)
        log_ttl: How long to store log data (seconds)
        max_connections: Maximum number of Redis connections
    """

    host: str = Field(
        default="localhost",
        description="Redis server hostname",
    )
    port: int = Field(
        default=6379,
        description="Redis server port",
        ge=1,
        le=65535,
    )
    password: Optional[str] = Field(
        default=None,
        description="Redis server password (optional)",
    )
    cache_duration: int = Field(
        default=3600,
        description="How long to cache authorization responses (seconds)",
        ge=1,
    )
    log_ttl: int = Field(
        default=86400,
        description="How long to store log data (seconds)",
        ge=1,
    )
    max_connections: int = Field(
        default=200,
        description="Maximum number of Redis connections in the pool",
        ge=1,
    )
    use_tls: bool = Field(
        default=True,
        description="Whether to use TLS for Redis connections",
    )


class KinesisConfig(BaseModel):
    """Kinesis configuration for data streaming and storage.

    This configuration includes both Kinesis Data Streams for high-throughput ingestion
    and Kinesis Firehose for S3 delivery.

    Attributes:
        metadata_stream_name: Firehose stream name for metadata records
        request_headers_stream_name: Firehose stream name for request headers
        request_body_stream_name: Firehose stream name for request bodies
        request_trailers_stream_name: Firehose stream name for request trailers
        response_headers_stream_name: Firehose stream name for response headers
        response_body_stream_name: Firehose stream name for response bodies
        response_trailers_stream_name: Firehose stream name for response trailers
        max_record_size: Maximum size in bytes for a single Kinesis record
    """

    metadata_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for metadata records",
    )
    request_headers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for request headers",
    )
    request_body_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for request bodies",
    )
    request_trailers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for request trailers",
    )
    response_headers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for response headers",
    )
    response_body_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for response bodies",
    )
    response_trailers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis Firehose stream name for response trailers",
    )
    max_record_size: int = Field(
        default=900000,
        description="Maximum size in bytes for single Kinesis record (900KB)",
        ge=1000,
    )


class AwsConfig(BaseModel):
    """AWS-related configuration settings.

    Attributes:
        xray_daemon_address: AWS X-Ray daemon address
        xray_log_group: AWS X-Ray log group
        xray_extra_log_groups: Additional AWS X-Ray log groups,
                               comma separated (optional)
        xray_enabled: Whether AWS X-Ray tracing is enabled
    """

    xray_daemon_address: str = Field(
        default="127.0.0.1:2000",
        description="AWS X-Ray daemon address",
    )
    xray_log_group: str = Field(
        default="/aws/xray/portunus",
        description="AWS X-Ray log group",
    )
    xray_extra_log_groups: Optional[str] = Field(
        default=None,
        description="Additional AWS X-Ray log group, comma separated (optional)",
    )
    xray_enabled: bool = Field(
        default=True,
        description="Whether AWS X-Ray tracing is enabled",
    )
    endpoint_url: str | None = Field(
        default=None,
        description="Intended for overriding client urls for testing with LocalStack",
    )


class RelayConfig(BaseModel):
    """WebSocket relay configuration settings.

    The upstream target (host, port, TLS) is provided per-connection via
    headers injected by each proxy's Envoy (x-portunus-target-host, etc.).
    This config only holds Portunus-level settings that apply to all connections.

    Attributes:
        max_message_size: Maximum WebSocket message size in bytes
        max_connection_lifetime: Maximum connection lifetime in seconds
    """

    max_message_size: int = Field(
        default=10_485_760,
        description="Maximum WebSocket message size in bytes (10MB)",
        ge=1024,
    )
    max_connection_lifetime: int = Field(
        default=3300,
        description="Maximum connection lifetime in seconds (55 min)",
        ge=60,
    )
    max_connections_per_instance: int = Field(
        default=25,
        description="Maximum concurrent WebSocket connections per instance",
        ge=1,
    )


class PortunusConfig(BaseModel):
    """Main configuration for the Portunus service.

    Attributes:
        redis: Redis configuration
        aws: AWS configuration
        log_level: Logging level
        api_key_header: Header name to use for the API key
        api_key_prefix: Prefix to use for the API key
    """

    # Service settings
    redis: RedisConfig = Field(
        default_factory=RedisConfig,
        description="Redis configuration",
    )
    aws: AwsConfig = Field(
        default_factory=AwsConfig,
        description="AWS configuration",
    )
    kinesis: KinesisConfig = Field(
        default_factory=KinesisConfig,
        description="Kinesis Firehose configuration",
    )
    relay: RelayConfig = Field(
        default_factory=RelayConfig,
        description="WebSocket relay configuration",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level",
    )
    api_key_header: str = Field(
        default="authorization",
        description="Header name to use for the API key",
    )
    api_key_prefix: str = Field(
        default="Bearer ",
        description="Prefix to use for the API key",
    )

    @field_validator("log_level")
    def validate_log_level(cls, v):
        """Validate log level is one of the standard levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()

    model_config = ConfigDict()

    @classmethod
    def model_config_customise_sources(
        cls, init_settings, env_settings, file_secret_settings
    ):
        """Customize settings sources to prioritize environment variables."""
        return env_settings, init_settings, file_secret_settings


@lru_cache()
def get_config() -> PortunusConfig:
    """Get the application configuration, using environment variables.

    The function is cached to avoid reloading the configuration on every call.

    Returns:
        PortunusConfig: The application configuration
    """
    redis = RedisConfig(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        password=os.environ.get("REDIS_PASSWORD", None),
        # cache auth to extend temporary AWS creds lifetime
        cache_duration=int(os.environ.get("CACHE_DURATION", "86400")),
        # keep log ttl short to prevent storage bloat
        log_ttl=int(os.environ.get("LOG_TTL", "3600")),
        max_connections=int(os.environ.get("REDIS_MAX_CONNECTIONS", "200")),
        use_tls=os.environ.get("REDIS_USE_TLS", "true").lower() == "true",
    )

    aws = AwsConfig(
        xray_daemon_address=os.environ.get("AWS_XRAY_DAEMON_ADDRESS", "127.0.0.1:2000"),
        xray_log_group=os.environ.get("AWS_XRAY_LOG_GROUP", "/aws/xray/portunus"),
        xray_extra_log_groups=os.environ.get("AWS_XRAY_EXTRA_LOG_GROUPS", None),
        xray_enabled=os.environ.get("AWS_XRAY_SDK_ENABLED", "true").lower() != "false",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL", None),
    )

    kinesis = KinesisConfig(
        metadata_stream_name=os.environ.get("KINESIS_METADATA_STREAM", None),
        request_headers_stream_name=os.environ.get(
            "KINESIS_REQUEST_HEADERS_STREAM", None
        ),
        request_body_stream_name=os.environ.get("KINESIS_REQUEST_BODY_STREAM", None),
        request_trailers_stream_name=os.environ.get(
            "KINESIS_REQUEST_TRAILERS_STREAM", None
        ),
        response_headers_stream_name=os.environ.get(
            "KINESIS_RESPONSE_HEADERS_STREAM", None
        ),
        response_body_stream_name=os.environ.get("KINESIS_RESPONSE_BODY_STREAM", None),
        response_trailers_stream_name=os.environ.get(
            "KINESIS_RESPONSE_TRAILERS_STREAM", None
        ),
        max_record_size=int(os.environ.get("KINESIS_MAX_RECORD_SIZE", "1000000")),
    )

    relay = RelayConfig(
        max_message_size=int(os.environ.get("WS_MAX_MESSAGE_SIZE", "10485760")),
        max_connection_lifetime=int(
            os.environ.get("WS_MAX_CONNECTION_LIFETIME", "3300")
        ),
    )

    return PortunusConfig(
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        api_key_header=os.environ.get("API_KEY_HEADER", "authorization"),
        api_key_prefix=os.environ.get("API_KEY_PREFIX", "Bearer "),
        redis=redis,
        aws=aws,
        kinesis=kinesis,
        relay=relay,
    )


# Create a singleton instance of the configuration
config = get_config()
