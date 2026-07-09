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
        # Must match the env-loader default in get_config() (1_000_000) so the
        # model default and the runtime path agree.
        default=1_000_000,
        description="Maximum size in bytes for a single Firehose record (1MB)",
        ge=1000,
    )

    def missing_required_streams(self) -> list[str]:
        """Return the ``FIREHOSE_*`` env-var names whose stream is unset.

        Every HTTP audit record type is published unconditionally on the
        request path, but each ``PublishService.build_*`` short-circuits to
        ``None`` (logging only a warning) when its stream is unset — so a task
        with these unset serves traffic while silently dropping 100% of audit
        records. This is the single source of truth used to fail fast at gRPC
        startup, so a misconfigured task (e.g. one still carrying the
        pre-migration ``KINESIS_*`` env vars, leaving ``FIREHOSE_*`` unset)
        never serves.

        The required set is exactly the seven streams the original FastAPI
        boot-guard required (#22, commit ``0c9ff50``).
        ``ws_summary_stream_name`` is deliberately excluded: it is a
        per-connection roll-up new to the gRPC/ext_proc path, and the
        underlying WebSocket frame payloads are still captured via the
        (required) request/response body streams, so an unset summary stream
        loses only connection-level stats, not the audit trail itself.

        Returns:
            The names of the ``FIREHOSE_*`` env vars whose stream is unset
            (an empty list when every required stream is configured).
        """
        required = {
            "FIREHOSE_METADATA_STREAM": self.metadata_stream_name,
            "FIREHOSE_REQUEST_HEADERS_STREAM": self.request_headers_stream_name,
            "FIREHOSE_REQUEST_BODY_STREAM": self.request_body_stream_name,
            "FIREHOSE_REQUEST_TRAILERS_STREAM": self.request_trailers_stream_name,
            "FIREHOSE_RESPONSE_HEADERS_STREAM": self.response_headers_stream_name,
            "FIREHOSE_RESPONSE_BODY_STREAM": self.response_body_stream_name,
            "FIREHOSE_RESPONSE_TRAILERS_STREAM": self.response_trailers_stream_name,
        }
        return [env_var for env_var, value in required.items() if not value]


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
            "header/metadata/sentinel submits."
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
    drop_sentinel_timeout_seconds: float = Field(
        default=1.0,
        description=(
            "How long the body-drop sentinel submit may wait for queue "
            "headroom. The sentinel uses the blocking (reserved-headroom) "
            "path so it survives the very saturation it reports; the "
            "timeout bounds the wait so a wedged sink cannot stall the "
            "ext_proc stream indefinitely."
        ),
        ge=0.0,
    )
    health_check_interval_seconds: float = Field(
        default=10.0,
        description=(
            "Interval for the dependency (Redis) health probe that drives "
            "the gRPC health status. 0 disables the monitor. A Portunus "
            "that is SERVING but would deny every Check (Redis down) must "
            "fail its health probe rather than 403 traffic indefinitely."
        ),
        ge=0.0,
    )
    health_check_timeout_seconds: float = Field(
        default=2.0,
        description="Per-probe timeout for the dependency health check",
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


class SigningConfig(BaseModel):
    """HTTP message-signing (KMS) throughput and memory bounds.

    Requested by the signing/auth lane (see shared/FIX-COORDINATION.md):
    ``signing_service`` reads these via ``config.signing`` (with matching
    fallback defaults) to size the dedicated KMS.Sign executor and cap
    concurrent buffered signing requests (mem-V2).

    Attributes:
        kms_executor_workers: Thread count of the dedicated KMS.Sign executor
        max_concurrent: Cap on concurrent signing requests (semaphore)
        acquire_timeout_s: How long a signing request waits for a slot before
            being shed (fail-closed)
    """

    kms_executor_workers: int = Field(
        default=16,
        description="Thread count of the dedicated KMS.Sign executor",
        ge=1,
    )
    max_concurrent: int = Field(
        default=32,
        description="Cap on concurrent signing requests (semaphore)",
        ge=1,
    )
    acquire_timeout_s: float = Field(
        default=2.0,
        description=(
            "How long a signing request waits for a semaphore slot before "
            "being shed (fail-closed deny)"
        ),
        gt=0.0,
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
    signing: SigningConfig = Field(
        default_factory=SigningConfig,
        description="KMS signing throughput / concurrency bounds",
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
        drop_sentinel_timeout_seconds=float(
            os.environ.get("GRPC_DROP_SENTINEL_TIMEOUT_SECONDS", "1.0")
        ),
        health_check_interval_seconds=float(
            os.environ.get("GRPC_HEALTH_CHECK_INTERVAL_SECONDS", "10.0")
        ),
        health_check_timeout_seconds=float(
            os.environ.get("GRPC_HEALTH_CHECK_TIMEOUT_SECONDS", "2.0")
        ),
        proxy_api_key=os.environ.get("GRPC_PROXY_API_KEY", ""),
        proxy_api_key_optional=(
            os.environ.get("GRPC_PROXY_API_KEY_OPTIONAL", "false").lower() == "true"
        ),
    )

    signing = SigningConfig(
        kms_executor_workers=int(
            os.environ.get("SIGNING_KMS_EXECUTOR_WORKERS", "16")
        ),
        max_concurrent=int(os.environ.get("SIGNING_MAX_CONCURRENT", "32")),
        acquire_timeout_s=float(os.environ.get("SIGNING_ACQUIRE_TIMEOUT_S", "2.0")),
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
        signing=signing,
    )


# Create a singleton instance of the configuration
config = get_config()
