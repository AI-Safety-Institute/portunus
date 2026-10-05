"""
Configuration module for the Portunus.

This module centralizes all configuration options for the Portunus service.
It loads configuration from environment variables with reasonable defaults and
provides validation and documentation for all options.
"""

import logging
import os
from functools import lru_cache
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

DEFAULT_FEDERATION_ROLE_PATH_PREFIX = "/portunus-fed/"


# Credential-carrying headers left out of audit header capture; the default
# the proxy's entrypoint used up to 0.11.0, now read by the backend.
DEFAULT_KNOWN_AUTH_HEADERS = "authorization,x-api-key,x-goog-api-key,api-key"


def _parse_header_names(value: str) -> frozenset[str]:
    """Parse a comma-separated list of header names into a lower-cased set."""
    return frozenset(name.strip().lower() for name in value.split(",") if name.strip())


class RedisConfig(BaseModel):
    """Redis configuration settings.

    Attributes:
        host: Redis server hostname
        port: Redis server port
        password: Redis server password (optional)
        cache_duration: How long to cache authorization responses (seconds)
        log_ttl: How long to store log data (seconds)
        max_connections: Maximum number of Redis connections
        pool_timeout_seconds: How long a command waits for a free connection
        health_check_interval_seconds: Idle time before a pooled connection
                                       is checked with PING
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
    pool_timeout_seconds: float = Field(
        default=1.0,
        description="How long a command waits for a free pooled connection "
        "before failing (the pool blocks rather than erroring at the cap)",
        gt=0,
    )
    health_check_interval_seconds: int = Field(
        default=30,
        description="PING a pooled connection before use if it has been idle "
        "this long (0 disables)",
        ge=0,
    )


class AuthCacheConfig(BaseModel):
    """In-process (L1) auth-result cache and full-auth fallback limits.

    The L1 cache sits in front of Redis. A revocation (secret rotation, cache
    flush) takes up to ``local_ttl_seconds`` to reach every task — never past
    the credential expiry.
    """

    local_ttl_seconds: float = Field(
        default=30.0,
        description="Seconds an auth result is served from process memory "
        "without consulting Redis (0 disables the L1 cache)",
        ge=0,
    )
    local_max_entries: int = Field(
        default=10000,
        description="LRU bound on the L1 cache",
        ge=0,
    )
    fallback_max_concurrent: int = Field(
        default=32,
        description="Max concurrent full authentications (STS + Secrets "
        "Manager) per process; bounds the stampede when Redis misbehaves",
        ge=1,
    )
    fallback_acquire_timeout_s: float = Field(
        default=1.0,
        description="Seconds to wait for a full-auth slot before shedding (503)",
        gt=0,
    )


class KinesisConfig(BaseModel):
    """Kinesis configuration for data streaming and storage.

    This configuration includes both Kinesis Data Streams for high-throughput ingestion
    and Kinesis Firehose for S3 delivery.

    Attributes:
        metadata_stream_name: Kinesis data stream for metadata records
        request_headers_stream_name: Kinesis data stream for request headers
        request_body_stream_name: Kinesis data stream for request bodies
        request_trailers_stream_name: Kinesis data stream for request trailers
        response_headers_stream_name: Kinesis data stream for response headers
        response_body_stream_name: Kinesis data stream for response bodies
        response_trailers_stream_name: Kinesis data stream for response trailers
        max_record_size: Maximum size in bytes for a single audit record
    """

    metadata_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for metadata records",
    )
    request_headers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for request headers",
    )
    request_body_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for request bodies",
    )
    request_trailers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for request trailers",
    )
    response_headers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for response headers",
    )
    response_body_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for response bodies",
    )
    response_trailers_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for response trailers",
    )
    ws_summary_stream_name: Optional[str] = Field(
        default=None,
        description="Kinesis data stream for per-WebSocket-connection summary records",
    )
    max_record_size: int = Field(
        # Must match get_config()'s env-loader default (1_000_000).
        default=1_000_000,
        description="Max bytes per audit record (KDS caps a record at 1 MiB)",
        ge=1000,
    )

    def missing_required_streams(self) -> list[str]:
        """Return the ``KINESIS_*`` env-var names whose stream is unset.

        Used to fail fast at gRPC startup: with a stream unset, the build path
        short-circuits to None and the task serves traffic while dropping 100%
        of that audit record type.

        ``ws_summary_stream_name`` is excluded from the required set: its frame
        payloads are still captured via the required request/response body
        streams, so an unset summary loses only connection-level stats.

        Returns:
            Unset required ``KINESIS_*`` env-var names (empty when all set).
        """
        required = {
            "KINESIS_METADATA_STREAM": self.metadata_stream_name,
            "KINESIS_REQUEST_HEADERS_STREAM": self.request_headers_stream_name,
            "KINESIS_REQUEST_BODY_STREAM": self.request_body_stream_name,
            "KINESIS_REQUEST_TRAILERS_STREAM": self.request_trailers_stream_name,
            "KINESIS_RESPONSE_HEADERS_STREAM": self.response_headers_stream_name,
            "KINESIS_RESPONSE_BODY_STREAM": self.response_body_stream_name,
            "KINESIS_RESPONSE_TRAILERS_STREAM": self.response_trailers_stream_name,
        }
        return [env_var for env_var, value in required.items() if not value]


class MetricsConfig(BaseModel):
    """CloudWatch EMF metrics; off by default so local runs and tests stay quiet."""

    enabled: bool = Field(default=False, description="Emit CloudWatch EMF metrics")
    namespace: str = Field(
        default="Portunus", description="CloudWatch namespace", min_length=1
    )
    service_name: str = Field(
        default="portunus",
        description="Value of the ServiceName dimension (Role comes from GRPC_ROLE)",
        min_length=1,
    )
    flush_interval_seconds: float = Field(
        default=60.0,
        description="Seconds between EMF flushes (CloudWatch stores 60 s periods)",
        gt=0.0,
    )


class AwsConfig(BaseModel):
    """AWS-related configuration settings."""

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
    audit_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Separate audit listener; unset retains the shared listener",
    )
    role: Literal["all", "auth", "audit"] = Field(
        default="all",
        description="Which servicers this process hosts: 'all' (ext_authz + "
        "ext_proc), 'auth' (ext_authz + health on port), or 'audit' (ext_proc "
        "+ health on audit_port, falling back to port). Run one 'auth' and one "
        "'audit' process to stop audit load sharing the auth event loop.",
    )
    audit_drop_on_pressure: bool = Field(
        default=False,
        description="Drop audit submissions immediately when their queue is full",
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
    drain_flush_reserve_seconds: float = Field(
        default=5.0,
        description=(
            "Slice of the SIGTERM grace reserved for flushing the publish "
            "queue after the gRPC stream drain. Envoy holds ext_proc streams "
            "open for its own (longer) drain, so ``server.stop`` consumes "
            "its whole budget on every busy stop; without a reserve the "
            "queue would get a 0-second flush window and cancel every "
            "buffered audit record even with a healthy sink."
        ),
        ge=0.0,
    )
    publish_queue_maxsize: int = Field(
        default=10_000,
        description="Publish queue record-count capacity (bodies + metadata)",
        ge=1,
    )
    publish_queue_body_capacity: int = Field(
        default=9_000,
        description=(
            "Record-count soft cap for droppable body submits; the headroom "
            "up to ``publish_queue_maxsize`` is reserved for blocking "
            "header/metadata submits."
        ),
        ge=0,
    )
    publish_queue_max_bytes: int = Field(
        default=256 * 1024 * 1024,
        description=(
            "Byte budget for raw body payloads retained by queued (and "
            "in-flight) publish tasks. Body submits drop once the budget is "
            "hit, whatever the record count — the record-count cap alone "
            "allows ~6.4 GiB of retained chunks (10k × ~750 KB), which "
            "drives the process into its cgroup OOM kill. Size this with "
            "headroom: building a record adds ~33% (base64) transiently."
        ),
        ge=1,
    )
    # Defaults are the load-tested settings: one worker draining up to 3000
    # records per batch with a 5 ms coalescing wait sustained 600 RPS per pod
    # with exact audit; smaller batches send about one record per PutRecords
    # call and collapse to roughly 100 RPS under load.
    publish_workers: Optional[int] = Field(
        default=1,
        description="Publisher workers; None uses the stream-based worker count",
        ge=1,
        le=64,
    )
    publish_batch_size: int = Field(
        default=3000,
        description="Maximum queued records grouped before per-stream publishing",
        ge=1,
        le=3000,
    )
    publish_coalesce_ms: float = Field(
        default=5.0,
        description="Delay in milliseconds between partial publisher batches",
        ge=0.0,
        le=100.0,
        allow_inf_nan=False,
    )
    publish_blocking_timeout_seconds: float = Field(
        default=5.0,
        description=(
            "Bound on every blocking publish submit issued from the "
            "ext_proc stream path (headers, trailers, metadata, WS "
            "summary). With a wedged sink the queue never drains; an "
            "unbounded submit would pin the Process coroutine (and the "
            "drain's WS-summary flush) forever. On timeout the record is "
            "dropped and counted (dropped_total + warning) — observable "
            "loss instead of a wedged stream/drain."
        ),
        gt=0.0,
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


class FederationConfig(BaseModel):
    """Settings for minting short-lived upstream tokens via federation roles.

    Attributes:
        allowed_account_ids: AWS accounts whose federation roles a secret may
            name. Empty disables token minting.
        role_path_prefix: IAM path every federation role ARN must start with
        sts_endpoint_url: STS endpoint for AssumeRole and GetWebIdentityToken.
            None means AWS_ENDPOINT_URL if set, else the regional endpoint.
    """

    allowed_account_ids: list[str] = Field(
        default_factory=list,
        description="AWS account IDs whose federation roles may be assumed",
    )
    role_path_prefix: str = Field(
        default=DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
        description="IAM path prefix required on federation role ARNs",
    )
    sts_endpoint_url: Optional[str] = Field(
        default=None,
        description="STS endpoint for federation calls (default: regional)",
    )

    @field_validator("allowed_account_ids")
    def validate_account_ids(cls, v: list[str]) -> list[str]:
        """Require 12-digit account IDs."""
        for account_id in v:
            if not (account_id.isdigit() and len(account_id) == 12):
                raise ValueError(f"Invalid AWS account ID: {account_id!r}")
        return v

    @field_validator("role_path_prefix")
    def validate_role_path_prefix(cls, v: str) -> str:
        """IAM paths start and end with a slash."""
        if not (v.startswith("/") and v.endswith("/")):
            raise ValueError("role_path_prefix must start and end with '/'")
        return v


class PortunusConfig(BaseModel):
    """Main configuration for the Portunus service.

    Attributes:
        redis: Redis configuration
        aws: AWS configuration
        federation: Federation token minting configuration
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
    metrics: MetricsConfig = Field(
        default_factory=MetricsConfig,
        description="CloudWatch EMF metrics configuration",
    )
    kinesis: KinesisConfig = Field(
        default_factory=KinesisConfig,
        description="Kinesis Data Streams audit publishing configuration",
    )
    grpc: GrpcConfig = Field(
        default_factory=GrpcConfig,
        description="gRPC server configuration",
    )
    auth_cache: AuthCacheConfig = Field(
        default_factory=AuthCacheConfig,
        description="In-process auth cache and full-auth fallback limits",
    )
    federation: FederationConfig = Field(
        default_factory=FederationConfig,
        description="Federation token minting configuration",
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
    known_auth_headers: frozenset[str] = Field(
        default=frozenset(DEFAULT_KNOWN_AUTH_HEADERS.split(",")),
        description=(
            "Lower-cased names of headers that carry credentials and are left "
            "out of audit header capture (KNOWN_AUTH_HEADERS, comma-separated). "
            "The configured api_key_header and the header the upstream "
            "credential is written to are always excluded as well."
        ),
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


def _split_csv(value: str) -> list[str]:
    """Split a comma-separated env var, dropping blanks."""
    return [item.strip() for item in value.split(",") if item.strip()]


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
        pool_timeout_seconds=float(os.environ.get("REDIS_POOL_TIMEOUT_SECONDS", "1.0")),
        health_check_interval_seconds=int(
            os.environ.get("REDIS_HEALTH_CHECK_INTERVAL_SECONDS", "30")
        ),
    )

    aws = AwsConfig(
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL", None),
    )

    metrics = MetricsConfig(
        enabled=os.environ.get("METRICS_ENABLED", "false").lower() == "true",
        namespace=os.environ.get("METRICS_NAMESPACE", "Portunus"),
        flush_interval_seconds=float(
            os.environ.get("METRICS_FLUSH_INTERVAL_SECONDS", "60")
        ),
        service_name=os.environ.get("METRICS_SERVICE_NAME", "portunus"),
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
        host=os.environ.get("GRPC_HOST", "127.0.0.1"),
        port=int(os.environ.get("GRPC_PORT", "9000")),
        audit_port=(
            int(os.environ["GRPC_AUDIT_PORT"])
            if "GRPC_AUDIT_PORT" in os.environ
            else None
        ),
        role=os.environ.get("GRPC_ROLE", "all"),  # type: ignore[arg-type]
        audit_drop_on_pressure=os.environ.get(
            "GRPC_AUDIT_DROP_ON_PRESSURE", "false"
        ).lower()
        == "true",
        max_concurrent_streams=int(
            os.environ.get("GRPC_MAX_CONCURRENT_STREAMS", "1000")
        ),
        graceful_shutdown_seconds=int(
            os.environ.get("GRPC_GRACEFUL_SHUTDOWN_SECONDS", "30")
        ),
        drain_flush_reserve_seconds=float(
            os.environ.get("GRPC_DRAIN_FLUSH_RESERVE_SECONDS", "5.0")
        ),
        publish_queue_maxsize=int(
            os.environ.get("GRPC_PUBLISH_QUEUE_MAXSIZE", "10000")
        ),
        publish_queue_body_capacity=int(
            os.environ.get("GRPC_PUBLISH_QUEUE_BODY_CAPACITY", "9000")
        ),
        publish_queue_max_bytes=int(
            os.environ.get("GRPC_PUBLISH_QUEUE_MAX_BYTES", str(256 * 1024 * 1024))
        ),
        publish_workers=int(os.environ.get("GRPC_PUBLISH_WORKERS", "1")),
        publish_batch_size=int(os.environ.get("GRPC_PUBLISH_BATCH_SIZE", "3000")),
        publish_coalesce_ms=float(os.environ.get("GRPC_PUBLISH_COALESCE_MS", "5")),
        publish_blocking_timeout_seconds=float(
            os.environ.get("GRPC_PUBLISH_BLOCKING_TIMEOUT_SECONDS", "5.0")
        ),
        proxy_api_key=os.environ.get("GRPC_PROXY_API_KEY", ""),
        proxy_api_key_optional=(
            os.environ.get("GRPC_PROXY_API_KEY_OPTIONAL", "false").lower() == "true"
        ),
    )

    auth_cache = AuthCacheConfig(
        local_ttl_seconds=float(os.environ.get("AUTH_LOCAL_CACHE_TTL_SECONDS", "30")),
        local_max_entries=int(os.environ.get("AUTH_LOCAL_CACHE_MAX_ENTRIES", "10000")),
        fallback_max_concurrent=int(
            os.environ.get("AUTH_FALLBACK_MAX_CONCURRENT", "32")
        ),
        fallback_acquire_timeout_s=float(
            os.environ.get("AUTH_FALLBACK_ACQUIRE_TIMEOUT_S", "1.0")
        ),
    )

    federation = FederationConfig(
        allowed_account_ids=_split_csv(
            os.environ.get("FEDERATION_ALLOWED_ACCOUNT_IDS", "")
        ),
        role_path_prefix=os.environ.get(
            "FEDERATION_ROLE_PATH_PREFIX", DEFAULT_FEDERATION_ROLE_PATH_PREFIX
        ),
        sts_endpoint_url=os.environ.get("FEDERATION_STS_ENDPOINT_URL", None),
    )

    return PortunusConfig(
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        api_key_header=os.environ.get("API_KEY_HEADER", "authorization"),
        api_key_prefix=os.environ.get("API_KEY_PREFIX", "Bearer "),
        known_auth_headers=_parse_header_names(
            os.environ.get("KNOWN_AUTH_HEADERS", DEFAULT_KNOWN_AUTH_HEADERS)
        ),
        proxy_header_prefix=os.environ.get("PORTUNUS_HEADER_PREFIX", "portunus"),
        redis=redis,
        aws=aws,
        metrics=metrics,
        kinesis=kinesis,
        grpc=grpc,
        auth_cache=auth_cache,
        federation=federation,
    )


# Create a singleton instance of the configuration
config = get_config()
