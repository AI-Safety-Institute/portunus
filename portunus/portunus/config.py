"""Portunus configuration loaded from environment variables."""

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


class FirehoseConfig(BaseModel):
    """Firehose direct-PUT configuration for log record publishing.

    Configures the per-component Firehose delivery stream names that Portunus
    publishes request/response log records to. S3 destinations and Glue ETL are
    provisioned separately (in the api-key-proxy CDK infra) and not configured here.

    Attributes:
        metadata_stream_name: Firehose delivery stream for metadata records
        request_headers_stream_name: Firehose delivery stream for request headers
        request_body_stream_name: Firehose delivery stream for request bodies
        request_trailers_stream_name: Firehose delivery stream for request trailers
        response_headers_stream_name: Firehose delivery stream for response headers
        response_body_stream_name: Firehose delivery stream for response bodies
        response_trailers_stream_name: Firehose delivery stream for response trailers
        ws_summary_stream_name: Stream name for per-connection WebSocket summaries
        max_record_size: Maximum size in bytes for a single Firehose record
    """

    metadata_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for metadata records",
    )
    request_headers_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for request headers",
    )
    request_body_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for request bodies",
    )
    request_trailers_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for request trailers",
    )
    response_headers_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for response headers",
    )
    response_body_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for response bodies",
    )
    response_trailers_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose delivery stream for response trailers",
    )
    ws_summary_stream_name: Optional[str] = Field(
        default=None,
        description="Firehose stream for one summary record per WebSocket connection",
    )
    max_record_size: int = Field(
        default=900000,
        description="Maximum size in bytes for single Firehose record (900KB)",
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
    """gRPC server config for Envoy ext_authz / ext_proc filters."""

    enabled: bool = Field(
        default=False,
        description="Whether to start the gRPC server",
    )
    host: str = Field(
        default="127.0.0.1",
        description=(
            "Interface the gRPC server binds to. Defaults to loopback for "
            "the sidecar topology where Envoy reaches Portunus on localhost. "
            "Set to ``0.0.0.0`` for docker-compose where Envoy and Portunus "
            "are separate containers reaching each other over a bridge "
            "network. (In our docker-compose the portunus container shares "
            "the proxy container's network namespace, so loopback works "
            "there too — this knob exists for non-shared-netns topologies.)"
        ),
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
    proxy_api_key_optional: bool = Field(
        default=False,
        description=(
            "Explicit opt-in to allow empty ``proxy_api_key``. Production "
            "must leave this False so a missing key fails closed."
        ),
    )


class PortunusConfig(BaseModel):
    """Top-level Portunus configuration."""

    # Service settings
    redis: RedisConfig = Field(
        default_factory=RedisConfig,
        description="Redis configuration",
    )
    aws: AwsConfig = Field(
        default_factory=AwsConfig,
        description="AWS configuration",
    )
    firehose: FirehoseConfig = Field(
        default_factory=FirehoseConfig,
        description="Firehose direct-PUT configuration",
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
    proxy_header_prefix: str = Field(
        default="portunus",
        description=(
            "Prefix for proxy-emitted response headers (e.g. ``x-{prefix}-error``). "
            "Must match the proxy container's PORTUNUS_HEADER_PREFIX."
        ),
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

    firehose = FirehoseConfig(
        metadata_stream_name=os.environ.get("FIREHOSE_METADATA_STREAM", None),
        request_headers_stream_name=os.environ.get(
            "FIREHOSE_REQUEST_HEADERS_STREAM", None
        ),
        request_body_stream_name=os.environ.get("FIREHOSE_REQUEST_BODY_STREAM", None),
        request_trailers_stream_name=os.environ.get(
            "FIREHOSE_REQUEST_TRAILERS_STREAM", None
        ),
        response_headers_stream_name=os.environ.get(
            "FIREHOSE_RESPONSE_HEADERS_STREAM", None
        ),
        response_body_stream_name=os.environ.get("FIREHOSE_RESPONSE_BODY_STREAM", None),
        response_trailers_stream_name=os.environ.get(
            "FIREHOSE_RESPONSE_TRAILERS_STREAM", None
        ),
        ws_summary_stream_name=os.environ.get("FIREHOSE_WS_SUMMARY_STREAM", None),
        max_record_size=int(os.environ.get("FIREHOSE_MAX_RECORD_SIZE", "1000000")),
    )

    grpc = GrpcConfig(
        enabled=os.environ.get("GRPC_ENABLED", "false").lower() == "true",
        host=os.environ.get("GRPC_HOST", "127.0.0.1"),
        port=int(os.environ.get("GRPC_PORT", "9000")),
        max_concurrent_streams=int(
            os.environ.get("GRPC_MAX_CONCURRENT_STREAMS", "1000")
        ),
        graceful_shutdown_seconds=int(
            os.environ.get("GRPC_GRACEFUL_SHUTDOWN_SECONDS", "30")
        ),
        proxy_api_key=os.environ.get("GRPC_PROXY_API_KEY", ""),
        proxy_api_key_optional=(
            os.environ.get("GRPC_PROXY_API_KEY_OPTIONAL", "false").lower() == "true"
        ),
    )

    return PortunusConfig(
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        api_key_header=os.environ.get("API_KEY_HEADER", "authorization"),
        api_key_prefix=os.environ.get("API_KEY_PREFIX", "Bearer "),
        proxy_header_prefix=os.environ.get("PORTUNUS_HEADER_PREFIX", "portunus"),
        redis=redis,
        aws=aws,
        firehose=firehose,
        grpc=grpc,
    )


# Create a singleton instance of the configuration
config = get_config()
