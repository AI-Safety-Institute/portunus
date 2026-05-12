"""
Data models for the Portunus.

This module contains dataclass models and Pydantic models that represent entities
and data structures used throughout the Portunus service. These models provide
type safety, validation, and conversion methods.

Note: Non-standard library imports are lazy-loaded to allow safe export to
environments like AWS Glue where dependencies may not be available.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Dict,
    List,
    Optional,
    Protocol,
    Union,
)

if TYPE_CHECKING:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError
else:
    try:
        from pydantic import BaseModel, ConfigDict, Field, ValidationError
    except ImportError:
        # Define minimal stubs for environments without pydantic
        def _field_stub(*args: Any, **kwargs: Any) -> None:
            """Stub for pydantic Field when pydantic is not available."""
            return None

        BaseModel = object  # type: ignore
        ConfigDict = dict  # type: ignore
        Field = _field_stub  # type: ignore
        ValidationError = Exception  # type: ignore

import logging

logger = logging.getLogger("api.access")


class RowLike(Protocol):
    """Protocol for Spark Row objects that can be converted to dicts."""

    def asDict(self) -> Dict[str, str]:
        """Convert Row to dict."""
        ...


@dataclass
class ParsedArn:
    """Result of parsing an AWS ARN."""

    account_id: str
    path_parts: Optional[List[str]] = None


@dataclass
class RequestSummary:
    """Summary of request data for notifications."""

    headers: Dict[str, str]
    size: int


@dataclass
class ResponseSummary:
    """Summary of response data for notifications."""

    headers: Dict[str, str]
    size: int


def decode_base64(value: str) -> bytes:
    """Decode a base64-encoded string to bytes, preserving binary data."""
    return base64.b64decode(value)


def _decode_b64_header(raw_headers: Dict[str, str], key: str) -> Optional[str]:
    """Decode a single base64-encoded header value to a UTF-8 string.

    Returns None if the key is missing or decoding fails.
    """
    if key not in raw_headers:
        return None
    try:
        return base64.b64decode(raw_headers[key]).decode("utf-8", errors="replace")
    except (binascii.Error, UnicodeDecodeError):
        return None


def _decode_b64_headers(
    raw_headers: Union[Dict[str, str], "RowLike"],
) -> tuple[Dict[str, Optional[str]], int]:
    """Decode all base64-encoded header values in a dict.

    Returns (decoded_dict, failure_count).
    """
    if hasattr(raw_headers, "asDict"):
        raw_headers = raw_headers.asDict()  # type: ignore[call-non-callable]  # guarded by hasattr; RowLike protocol

    result: Dict[str, Optional[str]] = {}
    failures = 0
    for key, value in raw_headers.items():
        try:
            result[key] = base64.b64decode(value).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            result[key] = None
            failures += 1
    return result, failures


def _decompress_b64_body(
    body_b64: str, content_encoding: Optional[str]
) -> tuple[Optional[str], bool]:
    """Base64-decode, optionally decompress, and UTF-8 decode a body.

    Returns (decoded_text, failed). On failure, decoded_text is None and failed is True.
    """
    import gzip
    import zlib

    try:
        body_bytes = base64.b64decode(body_b64)
    except (binascii.Error, UnicodeDecodeError):
        return None, True

    if content_encoding:
        encoding = content_encoding.lower()
        if "gzip" in encoding:
            try:
                body_bytes = gzip.decompress(body_bytes)
            except (OSError, EOFError):
                return None, True
        elif "deflate" in encoding:
            try:
                body_bytes = zlib.decompress(body_bytes)
            except (zlib.error, EOFError):
                return None, True

    try:
        return body_bytes.decode("utf-8"), False
    except UnicodeDecodeError:
        return None, True


@dataclass
class AwsCredentials:
    """AWS credential object containing access keys and optional session token.

    Attributes:
        access_key_id (str): AWS access key ID
        secret_access_key (str): AWS secret access key
        session_token (Optional[str]): Optional AWS session token for temporary
                                       credentials
        expiration (Optional[datetime]): When credentials expire (UTC)
    """

    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    expiration: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Validate credentials after initialization."""
        from portunus.exceptions import InputValidationError

        if not self.access_key_id:
            raise InputValidationError("access_key_id", "Access key ID cannot be empty")
        if not self.secret_access_key:
            raise InputValidationError(
                "secret_access_key", "Secret access key cannot be empty"
            )

    @staticmethod
    def _parse_expiration(expiration_str: Optional[str]) -> Optional[datetime]:
        """Parse an expiration string into a datetime object.

        Args:
            expiration_str: ISO-8601 formatted expiration timestamp

        Returns:
            Parsed datetime in UTC, or None if not provided or unparseable
        """
        if not expiration_str:
            return None

        try:
            # Parse ISO-8601 timestamp (handles various formats including Z suffix)
            dt = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
            # Ensure it's in UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            logger.warning(f"Could not parse credential expiration: {expiration_str}")
            return None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AwsCredentials":
        """Create AwsCredentials from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary containing credential keys
                "access_key_id", "secret_access_key", and optional "session_token"
                and "expiration"

        Returns:
            AwsCredentials: A new credentials object

        Raises:
            InputValidationError: If required fields are missing
        """
        return cls(
            access_key_id=data.get("access_key_id", ""),
            secret_access_key=data.get("secret_access_key", ""),
            session_token=data.get("session_token"),
            expiration=cls._parse_expiration(data.get("expiration")),
        )

    def is_valid(self) -> bool:
        """Check if credentials are valid (non-empty keys).

        Returns:
            bool: True if both access_key_id, secret_access_key are non-empty
        """
        return bool(self.access_key_id and self.secret_access_key)

    def seconds_until_expiration(self) -> Optional[int]:
        """Get the number of seconds until credentials expire.

        Returns:
            Optional[int]: Seconds until expiration, or None if no expiration set.
                          Returns 0 if already expired.
        """
        if not self.expiration:
            return None

        delta = (self.expiration - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(delta))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary with credential fields
        """
        return {
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key,
            "session_token": self.session_token,
            "expiration": self.expiration.isoformat() if self.expiration else None,
        }


@dataclass
class AuthPayload:
    """Authorization payload containing AWS credentials and a secret ARN.

    Attributes:
        raw (str): JSON string of AWS credentials
        credentials (AwsCredentials): Parsed AWS credentials
        secret_arn (str): ARN of the secret to retrieve
        target_host (Optional[str]): Expected target host for validation
    """

    raw: str
    "Used for cache key generation to allow for forward compatible cache busting"
    credentials: AwsCredentials
    secret_arn: str
    target_host: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate payload after initialization."""
        from portunus.exceptions import InputValidationError

        if not self.secret_arn:
            raise InputValidationError("secret_arn", "Secret ARN cannot be empty")

    @classmethod
    def from_contents(
        cls, raw_payload: str, target_host: Optional[str] = None
    ) -> "AuthPayload":
        """
        Create an AuthPayload from a base64 encoded payload.

        The proxy removes the Bearer prefix before sending this payload. The payload
        is expected to be a base64-encoded JSON string containing "credentials" and
        "secret_arn" fields.

        Args:
            raw_payload (str): Base64-encoded payload string
            target_host (Optional[str]): Target host from proxy configuration

        Returns:
            AuthPayload: A new authorization payload object

        Raises:
            PayloadError: If the payload is invalid or cannot be decoded
        """
        from portunus.exceptions import InputValidationError, PayloadError
        from portunus.services.payload_service import decode_payload

        try:
            decoded_payload = decode_payload(raw_payload)
            # Check for required fields
            if not isinstance(decoded_payload, dict):
                raise PayloadError("Invalid payload format")

            credentials = AwsCredentials.from_dict(
                decoded_payload.get("credentials", {})
            )
            secret_arn = decoded_payload.get("secret_arn", "")

            return cls(raw_payload, credentials, secret_arn, target_host)
        except InputValidationError as e:
            msg = f"Validation error in payload: {e.message}"
            raise PayloadError(msg) from e
        except Exception as e:
            # Never include raw_payload in the message: the base64 blob
            # contains temporary AWS credentials and would surface in error
            # responses, structured logs, and Envoy access logs. The `from e`
            # chain preserves the underlying decode error for debugging.
            msg = f"Failed to decode authorization payload: {type(e).__name__}"
            raise PayloadError(msg) from e

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary with payload fields
        """
        result = {
            "credentials": self.credentials.to_dict(),
            "secret_arn": self.secret_arn,
            "expiration": None,  # This is typically set when creating temporary creds
        }
        if self.target_host:
            result["target_host"] = self.target_host
        return result


@dataclass
class PrincipalInfo:
    """Principal identity information extracted from AWS ARN.

    Attributes:
        account_id (str): The AWS account ID
        principal (Optional[str]): The principal type and name
        session_name (Optional[str]): The session name if present
        project (str): The project name extracted from UserProfile_ roles
    """

    arn: str = "unknown"
    account_id: str = "unknown"
    principal: Optional[str] = None
    session_name: Optional[str] = None
    project: Optional[str] = None

    @classmethod
    def empty(cls) -> "PrincipalInfo":
        """Create an empty PrincipalInfo object with default values.

        Returns:
            PrincipalInfo: An empty principal info object
        """
        return cls()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PrincipalInfo":
        """Create a PrincipalInfo object from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary containing principal info fields

        Returns:
            PrincipalInfo: A new principal info object
        """
        return cls(
            arn=data["arn"],
            account_id=data["account_id"],
            principal=data["principal"],
            session_name=data["session_name"],
            project=data["project"],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            dict: Dictionary with principal info fields
        """
        return {
            "arn": self.arn,
            "account_id": self.account_id,
            "principal": self.principal,
            "session_name": self.session_name,
            "project": self.project,
        }


class SecretsManagerAuthPayload(BaseModel):
    """
    AWS SecretsManager payload for our proxy api keys.

    Each api key secret is either a simple string consisting entirely of the api key,
    or a json payload in this format
    """

    model_config = ConfigDict(populate_by_name=True)

    api_key: Annotated[str, Field(alias="secret")]
    host: Optional[str] = None
    signing_key: Optional[SigningKey] = None

    @classmethod
    def from_string(cls, input: str) -> SecretsManagerAuthPayload:
        try:
            secret_data: str = json.loads(input)
        except json.JSONDecodeError:
            logger.info("Secret is plaintext format")
            return cls(api_key=input)

        try:
            return cls.model_validate(secret_data)
        except ValidationError as e:
            logger.info(
                "JSON secret with unrecognised schema, using JSON as API key",
                exc_info=e,
            )
            return cls(api_key=input)


@dataclass
class SigningKey:
    provider_id: str
    """The id the provider assigned to this key.

    We pass this so the lab knows which public key this request was signed with"""
    kms_key_arn: str
    "Our KMS key to sign requests with"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class AuthResult:
    """Result of an authentication operation.

    Attributes:
        api_key (str): The API key retrieved from Secrets Manager
        principal_info (PrincipalInfo): Information about the authenticated principal
    """

    api_key: str
    signing_key: Optional[SigningKey]
    principal_info: PrincipalInfo

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthResult":
        """Create an AuthResult object from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary containing auth result fields

        Returns:
            AuthResult: A new auth result object
        """
        principal_info_data = data.get("principal_info", {})
        principal_info = PrincipalInfo.from_dict(principal_info_data)

        return cls(
            api_key=data.get("api_key", ""),
            signing_key=data.get("signing_key", None),
            principal_info=principal_info,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary with auth result fields
        """
        return asdict(self)

    @property
    def successful(self) -> bool:
        """Check if the authentication was successful.

        Returns:
            bool: True if api_key is non-empty, False otherwise
        """
        return bool(self.api_key)


# Request payload models for the new REST endpoints
class HeadersPayload(BaseModel):
    """Request payload model for headers endpoints (request/response).

    Attributes:
        headers: Dictionary of headers with base64-encoded values from Lua
        timestamp: Unix timestamp number when the event occurred
    """

    headers: Dict[str, str]
    timestamp: int

    def get_iso_timestamp(self) -> str:
        """Convert timestamp to ISO-8601 format if it's a Unix timestamp."""
        from portunus.util import unix_timestamp_to_iso

        return unix_timestamp_to_iso(self.timestamp)


class TrailersPayload(BaseModel):
    """Request payload model for trailers endpoints (request/response).

    Attributes:
        trailers: Dictionary of trailers with base64-encoded values from Lua
        timestamp: Unix timestamp number when the event occurred
    """

    trailers: Dict[str, str]
    timestamp: int

    def get_iso_timestamp(self) -> str:
        """Convert timestamp to ISO-8601 format if it's a Unix timestamp."""
        from portunus.util import unix_timestamp_to_iso

        return unix_timestamp_to_iso(self.timestamp)


# Kinesis record dataclasses - define the structure of published records


@dataclass
class MetadataRecord:
    """Metadata record for Kinesis stream containing request and principal information.

    This record is generated by Portunus when a request is first authorized and contains
    identity information extracted from the AWS credentials used for authentication.
    Published to the metadata Kinesis stream.

    Attributes:
        request_id: Unique request identifier (UUID format). Used to correlate logs
            across all streams.
        timestamp: ISO-8601 formatted timestamp when the request was received by the
            proxy. This is the canonical timestamp used for partitioning in ETL jobs.
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
            May differ slightly from timestamp due to processing delays.
        account_id: AWS account ID extracted from the principal ARN. None if principal
            information is unavailable (e.g., mock mode).
        principal: Principal type and name (e.g., "assumed-role/RoleName"). None if
            principal information is unavailable.
        principal_arn: Full principal ARN (e.g.
            "arn:aws:sts::123456789012:assumed-role/...").
            None if principal information is unavailable.
        project: Project name extracted from UserProfile_ pattern in role names. None
            if the role doesn't match the pattern or principal info is unavailable.
        session_name: Session name from assumed role ARNs. None if not present or
            principal information is unavailable.
        secret_arn: Full ARN of the AWS Secrets Manager secret used for the API
            key. None if not available. Downstream consumers parse the name
            from the ARN when needed.
    """

    request_id: str
    timestamp: str
    published_at: str
    account_id: Optional[str] = None
    principal: Optional[str] = None
    principal_arn: Optional[str] = None
    project: Optional[str] = None
    session_name: Optional[str] = None
    secret_arn: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "metadata",
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
            "account_id": self.account_id,
            "principal": self.principal,
            "principal_arn": self.principal_arn,
            "project": self.project,
            "session_name": self.session_name,
            "secret_arn": self.secret_arn,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
            {"name": "account_id", "type": "string"},
            {"name": "principal", "type": "string"},
            {"name": "principal_arn", "type": "string"},
            {"name": "project", "type": "string"},
            {"name": "session_name", "type": "string"},
            {"name": "secret_arn", "type": "string"},
        ]


@dataclass
class RequestHeadersRecord:
    """Request headers record for Kinesis stream containing HTTP request headers.

    This record is captured by the Envoy proxy via Lua script and published to the
    request-headers Kinesis stream. Headers are base64-encoded by Lua before publishing
    to safely handle binary or non-UTF-8 header values.

    Attributes:
        request_id: Unique request identifier (UUID format). Matches metadata stream.
        raw_headers: Complete dictionary of HTTP headers with base64-encoded values.
            Keys are lowercase header names. Includes pseudo-headers (prefixed with :)
            from HTTP/2. All values are base64-encoded strings.
        timestamp: ISO-8601 formatted timestamp when headers were captured (typically
            matches the metadata timestamp).
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
        content_type: Decoded content-type header value (UTF-8 string). Automatically
            decoded from raw_headers during __post_init__. None if header not present
            or decoding fails.
        method: Decoded HTTP method from :method pseudo-header (e.g., "GET", "POST").
            None if not present or decoding fails.
        path: Decoded request path from :path pseudo-header (e.g.
            "/v1/chat/completions"). None if not present or decoding fails.
        authority: Decoded authority from :authority pseudo-header (HTTP/2 equivalent
            of Host header). None if not present or decoding fails.
        user_agent: Decoded User-Agent header value. None if not present or decoding
            fails.
        content_encoding: Decoded content-encoding header (e.g., "gzip", "deflate").
            Indicates compression applied to request body. None if not present or
            decoding fails.
    """

    request_id: str
    raw_headers: Dict[str, str]
    timestamp: str
    published_at: str
    content_type: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    authority: Optional[str] = None
    user_agent: Optional[str] = None
    content_encoding: Optional[str] = None

    def __post_init__(self) -> None:
        """Decode headers from base64 after initialization."""
        self.content_type = _decode_b64_header(self.raw_headers, "content-type")
        self.method = _decode_b64_header(self.raw_headers, ":method")
        self.path = _decode_b64_header(self.raw_headers, ":path")
        self.authority = _decode_b64_header(self.raw_headers, ":authority")
        self.user_agent = _decode_b64_header(self.raw_headers, "user-agent")
        self.content_encoding = _decode_b64_header(self.raw_headers, "content-encoding")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "request_headers",
            "request_id": self.request_id,
            "raw_headers": self.raw_headers,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
            "content_type": self.content_type,
            "method": self.method,
            "path": self.path,
            "authority": self.authority,
            "user_agent": self.user_agent,
            "content_encoding": self.content_encoding,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "raw_headers", "type": "map<string,string>"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
            {"name": "content_type", "type": "string"},
            {"name": "method", "type": "string"},
            {"name": "path", "type": "string"},
            {"name": "authority", "type": "string"},
            {"name": "user_agent", "type": "string"},
            {"name": "content_encoding", "type": "string"},
        ]


@dataclass
class RequestBodyRecord:
    """Request body record for Kinesis stream containing HTTP request body data.

    This record is captured by the Envoy proxy via Lua script and published to the
    request-body Kinesis stream. Large bodies are automatically split into chunks to
    stay within Kinesis record size limits. Each chunk is published as a separate
    record.

    Body data is base64-encoded by Lua before publishing to safely handle
    binary content.

    Attributes:
        request_id: Unique request identifier (UUID format). Matches metadata stream.
        body: Base64-encoded body content for this chunk. May contain compressed data
            if content-encoding header indicates compression (see request headers).
        body_size: Size of this chunk's body in bytes (after base64 encoding). Note
            this is the size of the encoded string, not the original binary data.
        timestamp: ISO-8601 formatted timestamp when body was captured.
        chunk_id: Zero-based index of this chunk. 0 for first chunk, incremented for
            subsequent chunks. ETL jobs currently only process chunk_id=0.
        num_chunks: Total number of chunks for this request body. If > 1, the body
            was split across multiple records. ETL jobs set a 'truncated' flag when
            num_chunks > 1 to indicate incomplete data.
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
    """

    request_id: str
    body: str
    body_size: int
    timestamp: str
    chunk_id: int
    num_chunks: int
    published_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "request_body",
            "request_id": self.request_id,
            "body": self.body,
            "body_size": self.body_size,
            "chunk_id": self.chunk_id,
            "num_chunks": self.num_chunks,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "body", "type": "string"},
            {"name": "body_size", "type": "bigint"},
            {"name": "chunk_id", "type": "bigint"},
            {"name": "num_chunks", "type": "bigint"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
        ]


@dataclass
class RequestTrailersRecord:
    """Request trailers record for Kinesis stream containing HTTP request trailers.

    This record is captured by the Envoy proxy via Lua script and published to the
    request-trailers Kinesis stream. Trailers are HTTP headers that appear after the
    message body in chunked transfer encoding. They are relatively uncommon in practice.

    Attributes:
        request_id: Unique request identifier (UUID format). Matches metadata stream.
        trailers: Dictionary of trailer name-value pairs. Keys are lowercase trailer
            names. Values may be base64-encoded depending on implementation.
        timestamp: ISO-8601 formatted timestamp when trailers were captured.
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
    """

    request_id: str
    trailers: Dict[str, str]
    timestamp: str
    published_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "request_trailers",
            "request_id": self.request_id,
            "trailers": self.trailers,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "trailers", "type": "map<string,string>"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
        ]


@dataclass
class ResponseHeadersRecord:
    """Response headers record for Kinesis stream containing HTTP response headers.

    This record is captured by the Envoy proxy via Lua script and published to the
    response-headers Kinesis stream after receiving headers from the upstream API.
    Headers are base64-encoded by Lua before publishing to safely handle binary or
    non-UTF-8 header values.

    Attributes:
        request_id: Unique request identifier (UUID format). Matches metadata stream.
        raw_headers: Complete dictionary of HTTP response headers with base64-encoded
            values. Keys are lowercase header names. Includes pseudo-headers (prefixed
            with :) from HTTP/2. All values are base64-encoded strings.
        timestamp: ISO-8601 formatted timestamp when response headers were captured.
            May differ from request timestamp by the upstream API latency.
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
        server: Decoded Server header value (e.g., "uvicorn"). Automatically decoded
            from raw_headers during __post_init__. None if header not present or
            decoding fails.
        status: Decoded HTTP status code from :status pseudo-header (e.g., "200",
            "404"). None if not present or decoding fails.
        content_length: Decoded Content-Length header value as string. Indicates the
            size of the response body in bytes. None if not present (e.g., chunked
            encoding) or decoding fails.
        content_type: Decoded Content-Type header value (e.g., "application/json").
            None if not present or decoding fails.
        content_encoding: Decoded content-encoding header (e.g., "gzip", "deflate").
            Indicates compression applied to response body. None if not present or
            decoding fails.
    """

    request_id: str
    raw_headers: Dict[str, str]
    timestamp: str
    published_at: str
    server: Optional[str] = None
    status: Optional[str] = None
    content_length: Optional[str] = None
    content_type: Optional[str] = None
    content_encoding: Optional[str] = None

    def __post_init__(self) -> None:
        """Decode headers from base64 after initialization."""
        self.server = _decode_b64_header(self.raw_headers, "server")
        self.status = _decode_b64_header(self.raw_headers, ":status")
        self.content_length = _decode_b64_header(self.raw_headers, "content-length")
        self.content_type = _decode_b64_header(self.raw_headers, "content-type")
        self.content_encoding = _decode_b64_header(self.raw_headers, "content-encoding")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "response_headers",
            "request_id": self.request_id,
            "raw_headers": self.raw_headers,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
            "server": self.server,
            "status": self.status,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "content_encoding": self.content_encoding,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "raw_headers", "type": "map<string,string>"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
            {"name": "server", "type": "string"},
            {"name": "status", "type": "string"},
            {"name": "content_length", "type": "string"},
            {"name": "content_type", "type": "string"},
            {"name": "content_encoding", "type": "string"},
        ]


@dataclass
class ResponseBodyRecord:
    """Response body record for Kinesis stream containing HTTP response body data.

    This record is captured by the Envoy proxy via Lua script and published to the
    response-body Kinesis stream. For streaming responses (e.g., Server-Sent Events),
    each chunk is published as it arrives. Large responses are automatically split into
    chunks to stay within Kinesis record size limits.

    Body data is base64-encoded by Lua before publishing to safely handle
    binary content.

    Attributes:
        request_id: Unique request identifier (UUID format). Matches metadata stream.
        body: Base64-encoded body content for this chunk. May contain compressed data
            if content-encoding header indicates compression (see response headers).
            For streaming responses, contains the data received in that stream chunk.
        body_size: Size of this chunk's body in bytes (after base64 encoding). Note
            this is the size of the encoded string, not the original binary data.
        timestamp: ISO-8601 formatted timestamp when this body chunk was captured.
            For streaming responses, each chunk has its own timestamp indicating when
            it was received.
        chunk_id: Zero-based index of this chunk. 0 for first chunk, incremented for
            subsequent chunks. For streaming responses, increments with each received
            chunk. ETL jobs currently only process chunk_id=0.
        num_chunks: Total number of chunks for this response body. If > 1, the body
            was split across multiple records. For streaming responses, this may not
            be known until the final chunk. ETL jobs set a 'truncated' flag when
            num_chunks > 1 to indicate incomplete data.
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
    """

    request_id: str
    body: str
    body_size: int
    timestamp: str
    chunk_id: int
    num_chunks: int
    published_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "response_body",
            "request_id": self.request_id,
            "body": self.body,
            "body_size": self.body_size,
            "chunk_id": self.chunk_id,
            "num_chunks": self.num_chunks,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "body", "type": "string"},
            {"name": "body_size", "type": "bigint"},
            {"name": "chunk_id", "type": "bigint"},
            {"name": "num_chunks", "type": "bigint"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
        ]


@dataclass
class ResponseTrailersRecord:
    """Response trailers record for Kinesis stream containing HTTP response trailers.

    This record is captured by the Envoy proxy via Lua script and published to the
    response-trailers Kinesis stream. Trailers are HTTP headers that appear after the
    message body in chunked transfer encoding. They are commonly used in streaming
    responses to send metadata after the body is complete.

    Attributes:
        request_id: Unique request identifier (UUID format). Matches metadata stream.
        trailers: Dictionary of trailer name-value pairs. Keys are lowercase trailer
            names. Values may be base64-encoded depending on implementation.
        timestamp: ISO-8601 formatted timestamp when trailers were captured.
        published_at: ISO-8601 timestamp when this record was published to Kinesis.
    """

    request_id: str
    trailers: Dict[str, str]
    timestamp: str
    published_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Kinesis publishing."""
        return {
            "record_type": "response_trailers",
            "request_id": self.request_id,
            "trailers": self.trailers,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "trailers", "type": "map<string,string>"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
        ]


@dataclass
class JoinedLogRecord:
    """Joined log record combining all streams for analysis.

    This record represents the output of the Glue ETL job (process_raw_data.py) that
    joins all log streams (metadata, request headers/body, response headers/body)
    by request_id using INNER joins. Only complete transactions with all streams
    present are included in the output.

    The schema is generated dynamically from the source record schemas by:
    1. Using metadata timestamp as the canonical timestamp (unprefixed)
    2. Adding stream-specific prefixes (metadata_, request_headers_, request_body_...)
    3. Dropping internal fields (record_type, published_at from non-metadata streams)
    4. Adding ETL metadata (etl_processed_at, partition columns)

    IMPORTANT LIMITATIONS:
    - Incomplete transactions (missing any stream) are excluded
    - Trailers are currently not included in the joined data
    - Response timing: responses arriving more than MINUTES_TO_PROCESS after requests
      may be filtered out and cause incomplete transactions

    All body data remains base64-encoded. Raw header dictionaries remain as maps of
    base64-encoded values. Individual header fields are decoded for convenience.
    """

    # Core request metadata (from MetadataRecord)
    # request_id and timestamp are not prefixed (used for joins and partitioning)

    # UUID format, correlates all streams for this transaction
    request_id: str

    # ISO-8601 when request was received; used for
    # partitioning (stored as timestamp type in Glue)
    timestamp: str

    # Flattened metadata fields (with metadata_ prefix)
    metadata_published_at: str
    metadata_account_id: Optional[str]
    metadata_principal: Optional[str]
    metadata_principal_arn: Optional[str]
    metadata_project: Optional[str]
    metadata_session_name: Optional[str]
    metadata_secret_arn: Optional[str]

    # Request headers (from RequestHeadersRecord with request_headers_ prefix)
    request_headers_raw_headers: Union[Dict[str, str], RowLike]
    request_headers_timestamp: str
    request_headers_content_type: Optional[str]
    request_headers_method: Optional[str]
    request_headers_path: Optional[str]
    request_headers_authority: Optional[str]
    request_headers_user_agent: Optional[str]
    request_headers_content_encoding: Optional[str]

    # Request body (from RequestBodyRecord with request_body_ prefix)
    request_body_body: str
    request_body_body_size: int
    request_body_num_chunks: int
    request_body_truncated: bool
    request_body_timestamp: str

    # Response headers (from ResponseHeadersRecord with response_headers_ prefix)
    response_headers_raw_headers: Union[Dict[str, str], RowLike]
    response_headers_timestamp: str
    response_headers_server: Optional[str]
    response_headers_status: Optional[str]
    response_headers_content_length: Optional[str]
    response_headers_content_type: Optional[str]
    response_headers_content_encoding: Optional[str]

    # Response body (from ResponseBodyRecord with response_body_ prefix)
    response_body_body: str
    response_body_body_size: int
    response_body_num_chunks: int
    response_body_truncated: bool
    response_body_timestamp: str

    # ETL metadata (added by Glue when raw data is processed)
    etl_processed_at: Optional[str] = None

    # Decoded fields (populated by decode/decompress methods during ETL)
    request_headers_decoded: Optional[Dict[str, str | None]] = None
    request_body_decoded: Optional[str] = None
    response_headers_decoded: Optional[Dict[str, str | None]] = None
    response_body_decoded: Optional[str] = None

    # Decode failure tracking (populated during ETL)
    request_headers_decode_failure: bool = False
    request_body_decode_failure: bool = False
    response_headers_decode_failure: bool = False
    response_body_decode_failure: bool = False

    # Partition columns (derived from timestamp during ETL, optional until written)
    year: Optional[int] = None
    month: Optional[int] = None
    day: Optional[int] = None
    hour: Optional[int] = None

    def decode_request_headers(self) -> int:
        """Decode base64-encoded request headers and populate request_headers_decoded.

        Returns:
            Number of headers that failed to decode
        """
        decoded, failures = _decode_b64_headers(self.request_headers_raw_headers)
        self.request_headers_decoded = decoded
        self.request_headers_decode_failure = failures > 0
        return failures

    def decode_response_headers(self) -> int:
        """Decode base64-encoded response headers and populate response_headers_decoded.

        Returns:
            Number of headers that failed to decode
        """
        decoded, failures = _decode_b64_headers(self.response_headers_raw_headers)
        self.response_headers_decoded = decoded
        self.response_headers_decode_failure = failures > 0
        return failures

    def decompress_request_body(self) -> bool:
        """Decompress and decode request body and populate request_body_decoded.

        Returns:
            True if decoding succeeded, False otherwise
        """
        decoded, failed = _decompress_b64_body(
            self.request_body_body, self.request_headers_content_encoding
        )
        self.request_body_decoded = decoded
        self.request_body_decode_failure = failed
        return not failed

    def decompress_response_body(self) -> bool:
        """Decompress and decode response body and populate response_body_decoded.

        Returns:
            True if decoding succeeded, False otherwise
        """
        decoded, failed = _decompress_b64_body(
            self.response_body_body, self.response_headers_content_encoding
        )
        self.response_body_decoded = decoded
        self.response_body_decode_failure = failed
        return not failed

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for joined log records."""
        return [
            # Core request metadata
            {"name": "request_id", "type": "string"},
            {"name": "timestamp", "type": "timestamp"},
            # Flattened metadata fields (with metadata_ prefix)
            {"name": "metadata_published_at", "type": "string"},
            {"name": "metadata_account_id", "type": "string"},
            {"name": "metadata_principal", "type": "string"},
            {"name": "metadata_principal_arn", "type": "string"},
            {"name": "metadata_project", "type": "string"},
            {"name": "metadata_session_name", "type": "string"},
            {"name": "metadata_secret_arn", "type": "string"},
            # Request headers data
            {"name": "request_headers_raw_headers", "type": "map<string,string>"},
            {"name": "request_headers_decoded", "type": "map<string,string>"},
            {"name": "request_headers_timestamp", "type": "timestamp"},
            {"name": "request_headers_content_type", "type": "string"},
            {"name": "request_headers_method", "type": "string"},
            {"name": "request_headers_path", "type": "string"},
            {"name": "request_headers_authority", "type": "string"},
            {"name": "request_headers_user_agent", "type": "string"},
            {"name": "request_headers_content_encoding", "type": "string"},
            # Request body data
            {"name": "request_body_body", "type": "string"},
            {"name": "request_body_decoded", "type": "string"},
            {"name": "request_body_body_size", "type": "bigint"},
            {"name": "request_body_num_chunks", "type": "bigint"},
            {"name": "request_body_truncated", "type": "boolean"},
            {"name": "request_body_timestamp", "type": "timestamp"},
            # Response headers data
            {"name": "response_headers_raw_headers", "type": "map<string,string>"},
            {"name": "response_headers_decoded", "type": "map<string,string>"},
            {"name": "response_headers_timestamp", "type": "timestamp"},
            {"name": "response_headers_server", "type": "string"},
            {"name": "response_headers_status", "type": "string"},
            {"name": "response_headers_content_length", "type": "string"},
            {"name": "response_headers_content_type", "type": "string"},
            {"name": "response_headers_content_encoding", "type": "string"},
            # Response body data
            {"name": "response_body_body", "type": "string"},
            {"name": "response_body_decoded", "type": "string"},
            {"name": "response_body_body_size", "type": "bigint"},
            {"name": "response_body_num_chunks", "type": "bigint"},
            {"name": "response_body_truncated", "type": "boolean"},
            {"name": "response_body_timestamp", "type": "timestamp"},
            # ETL metadata
            {"name": "etl_processed_at", "type": "string"},
            # Decode failure tracking
            {"name": "request_headers_decode_failure", "type": "boolean"},
            {"name": "request_body_decode_failure", "type": "boolean"},
            {"name": "response_headers_decode_failure", "type": "boolean"},
            {"name": "response_body_decode_failure", "type": "boolean"},
            # Partition columns (derived from timestamp during ETL)
            {"name": "year", "type": "int"},
            {"name": "month", "type": "int"},
            {"name": "day", "type": "int"},
            {"name": "hour", "type": "int"},
        ]

    @classmethod
    def partition_keys(cls) -> List[Dict[str, str]]:
        """Return Glue partition key schema for partitioning by timestamp.

        These columns are derived from the timestamp field during ETL processing
        and used for efficient Athena queries. They are kept separate from the
        main data schema since they are computed fields used for data organization.

        Returns:
            List of partition key definitions (name, type pairs) in Glue format
        """
        return [
            {"name": "year", "type": "int"},
            {"name": "month", "type": "int"},
            {"name": "day", "type": "int"},
            {"name": "hour", "type": "int"},
        ]

    @classmethod
    def partition_key_names(cls) -> List[str]:
        """Return just the partition column names.

        Convenience method for filtering, SQL generation, Spark operations, etc.

        Returns:
            List of partition column names
        """
        return [col["name"] for col in cls.partition_keys()]

    @classmethod
    def partition_path_from_datetime(cls, dt, zero_pad: bool = False) -> str:
        """Build S3 partition path string from a datetime.

        Returns path in format: year=YYYY/month=M/day=D/hour=H/ (or zero-padded if
        requested)

        IMPORTANT: Two different systems use different padding formats:
        - Spark (OUTPUT): Non-zero-padded (month=4) - default for this method
        - Kinesis Firehose (INPUT): Zero-padded (month=04) - use zero_pad=True

        Kinesis Firehose uses zero-padding because it extracts partition values from
        ISO timestamp strings. Spark uses integer columns which write without padding.

        Args:
            dt: Datetime to extract partition values from
            zero_pad: If True, zero-pad month/day/hour to 2 digits
                      (for Kinesis Firehose).
                      If False (default), use Spark's non-padded format
                      (for OUTPUT data).

        Returns:
            S3 partition path string

        Examples:
            >>> from datetime import datetime
            >>> dt = datetime(2025, 11, 4, 15, 30, 0)
            >>> JoinedLogRecord.partition_path_from_datetime(dt)
            'year=2025/month=11/day=4/hour=15/'
            >>> JoinedLogRecord.partition_path_from_datetime(dt, zero_pad=True)
            'year=2025/month=11/day=04/hour=15/'
        """
        if zero_pad:
            return (
                f"year={dt.year}/"
                f"month={str(dt.month).zfill(2)}/"
                f"day={str(dt.day).zfill(2)}/"
                f"hour={str(dt.hour).zfill(2)}/"
            )
        else:
            return f"year={dt.year}/month={dt.month}/day={dt.day}/hour={dt.hour}/"

    @classmethod
    def partition_column_expression(cls, column: str) -> str:
        """Return Spark SQL expression to extract partition column from timestamp.

        Used in ETL jobs to derive partition columns from the main timestamp field.

        Args:
            column: Partition column name (year, month, day, hour)

        Returns:
            Spark SQL expression string
        """
        if column not in cls.partition_key_names():
            raise ValueError(f"Invalid partition column name: {column}")
        return f"{column}(timestamp)"
