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
        ws_summary_stream_name: Stream name for per-connection WebSocket summaries
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
    ws_summary_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis stream for one summary record per WebSocket connection",
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


class GrpcConfig(BaseModel):
    """gRPC server configuration for Envoy ext_authz / ext_proc filters.

    The gRPC server runs alongside the existing FastAPI app and serves
    Envoy's external_authorization_v3 and external_processor_v3 services.
    It is opt-in via ``enabled`` so existing deployments aren't affected
    until they explicitly turn it on.

    Attributes:
        enabled: Whether to start the gRPC server alongside FastAPI.
        port: TCP port the gRPC server binds to.
        max_concurrent_streams: Per-connection HTTP/2 stream limit. Envoy
            opens one stream per request for ext_authz and one per stream
            for ext_proc, so the limit should comfortably exceed the
            expected concurrent-request count from any one Envoy task.
        graceful_shutdown_seconds: How long to give in-flight RPCs to
            complete on SIGTERM before forcing termination.
        proxy_api_key: Pre-shared key proving the caller is a sanctioned
            Envoy proxy. The proxy injects this as gRPC ``initial_metadata``
            on every Check / Process call under the ``x-portunus-proxy-key``
            metadata key; the servicer rejects the call with
            ``PERMISSION_DENIED`` if missing or wrong. Service Connect
            namespace membership gates network reachability, but the
            namespace is broader than "the api-key-proxy fleet" (any
            tenant-001 service is in it). This key is the identity factor.
            When empty, the validation is skipped — only do that in tests.
    """

    enabled: bool = Field(
        default=False,
        description="Whether to start the gRPC server",
    )
    port: int = Field(
        default=9000,
        description="TCP port the gRPC server binds to",
        ge=1,
        le=65535,
    )
    max_concurrent_streams: int = Field(
        default=1000,
        description="Per-connection HTTP/2 stream limit",
        ge=1,
    )
    graceful_shutdown_seconds: int = Field(
        default=30,
        description="Grace period for in-flight RPCs on SIGTERM",
        ge=0,
    )
    proxy_api_key: str = Field(
        default="",
        description=(
            "Pre-shared key the proxy presents as `x-portunus-proxy-key` "
            "gRPC metadata. Empty disables validation (tests only)."
        ),
    )


class PortunusConfig(BaseModel):
    """Main configuration for the Portunus service.

    Attributes:
        redis: Redis configuration
        aws: AWS configuration
        log_level: Logging level
        api_key_header: Header name to use for the API key
        api_key_prefix: Prefix to use for the API key
        grpc: gRPC server configuration (Envoy ext_authz / ext_proc)
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
    grpc: GrpcConfig = Field(
        default_factory=GrpcConfig,
        description="gRPC server configuration",
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
        ws_summary_stream_name=os.environ.get("KINESIS_WS_SUMMARY_STREAM", None),
        max_record_size=int(os.environ.get("KINESIS_MAX_RECORD_SIZE", "1000000")),
    )

    grpc = GrpcConfig(
        enabled=os.environ.get("GRPC_ENABLED", "false").lower() == "true",
        port=int(os.environ.get("GRPC_PORT", "9000")),
        max_concurrent_streams=int(
            os.environ.get("GRPC_MAX_CONCURRENT_STREAMS", "1000")
        ),
        graceful_shutdown_seconds=int(
            os.environ.get("GRPC_GRACEFUL_SHUTDOWN_SECONDS", "30")
        ),
        proxy_api_key=os.environ.get("GRPC_PROXY_API_KEY", ""),
    )

    return PortunusConfig(
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        api_key_header=os.environ.get("API_KEY_HEADER", "authorization"),
        api_key_prefix=os.environ.get("API_KEY_PREFIX", "Bearer "),
        redis=redis,
        aws=aws,
        kinesis=kinesis,
        grpc=grpc,
    )


# Create a singleton instance of the configuration
config = get_config()
