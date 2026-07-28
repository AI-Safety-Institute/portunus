"""Data models for Portunus.

Non-standard library imports are lazy-loaded so this module can be
exported standalone to environments like AWS Glue where heavy
dependencies aren't available.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import zlib
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


_EVENTSTREAM_CONTENT_TYPE = "application/vnd.amazon.eventstream"


def _eventstream_payload_to_sse_line(payload: bytes) -> Optional[str]:
    r"""Convert one eventstream message payload to an SSE ``data: {...}\n`` line.

    The payload is the Bedrock envelope ``{"bytes": "<base64 inner event>"}``;
    returns the inner event as a single compact SSE line, or None when the
    message isn't a usable ``bytes`` envelope (Bedrock emits non-``bytes``
    exception/throttling shapes mid-stream, which are skipped).
    """
    try:
        envelope = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not (isinstance(envelope, dict) and (inner_b64 := envelope.get("bytes"))):
        return None
    try:
        inner_str = base64.b64decode(inner_b64).decode("utf-8")
    except (TypeError, ValueError, binascii.Error) as exc:
        logger.warning(
            "Skipping malformed eventstream message: %s", exc.__class__.__name__
        )
        return None
    # SSE-injection guard: reject non-object inners and inners with literal
    # control chars (forbidden by RFC 8259); re-serializing keeps each SSE
    # event on one data line.
    try:
        inner = json.loads(inner_str)
    except json.JSONDecodeError:
        return None
    if not isinstance(inner, dict):
        return None
    return f"data: {json.dumps(inner, separators=(',', ':'))}\n"


def _parse_vnd_amazon_eventstream(body_bytes: bytes) -> Optional[str]:
    r"""Unwrap eventstream framing into SSE ``data: {...}\n`` lines.

    Framing is parsed by botocore's ``EventStreamBuffer`` (the same path boto3
    uses for Bedrock streaming). One SSE line per inner ``bytes`` event;
    non-``bytes`` messages are skipped (see ``_eventstream_payload_to_sse_line``).

    Returns None on decode failure (caller maps to
    ``response_body_decode_failure``): when no complete message parsed, or when
    the body ends in a truncated trailing frame (see truncation guard below).
    A non-None result means every input byte was in a complete frame.

    A ``ParserError`` from a corrupt frame *after* at least one message parsed
    (e.g. mid-stream CRC mismatch, which botocore validates) is best-effort:
    events recovered before it are returned rather than discarding the body.
    """
    # Lazy import per module convention: keep `import portunus.models` free of
    # third-party imports. botocore is present in both run targets (service
    # depends on it; Glue preinstalls boto3).
    from botocore.eventstream import EventStreamBuffer, ParserError

    buffer = EventStreamBuffer()
    buffer.add_data(body_bytes)
    sse_lines: list[str] = []
    parsed_any = False
    consumed = 0
    try:
        for message in buffer:
            parsed_any = True
            # total_length spans the whole on-wire frame (prelude + headers +
            # payload + both CRCs), so the running sum tracks bytes consumed by
            # complete frames — the basis for the truncation guard below.
            # (botocore-stubs mistypes ``prelude`` as ``int``; hence the ignore.)
            consumed += message.prelude.total_length  # type: ignore[attr-defined]
            line = _eventstream_payload_to_sse_line(message.payload)
            if line is not None:
                sse_lines.append(line)
    except ParserError as exc:
        if not parsed_any:
            logger.warning("eventstream parse failed: %s", exc.__class__.__name__)
            return None
        # Corrupt frame after a valid prefix (e.g. CRC mismatch): keep events
        # decoded so far. NOT the truncation path — a corrupt frame also leaves
        # a residual, but is deliberately recovered as a partial success, so
        # the guard below must not run here.
        logger.warning(
            "eventstream corrupt after %d message(s), keeping partial: %s",
            len(sse_lines),
            exc.__class__.__name__,
        )
        return "".join(sse_lines)
    if not parsed_any:
        return None
    # Truncation guard. botocore's EventStreamBuffer ends iteration with a bare
    # StopIteration the instant the remaining bytes are too few for the next
    # complete frame — indistinguishable from a clean end of stream. So a
    # truncated trailing frame (disconnect, reset, timeout, body-size cap) looks
    # like success and silently drops the token-bearing tail (Anthropic's
    # usage.output_tokens live in the near-final message_delta). Complete frames
    # account for every input byte, so any residual is an incomplete tail.
    residual = len(body_bytes) - consumed
    if residual > 0:
        logger.warning(
            "eventstream truncated: %d trailing byte(s) after %d complete "
            "message(s) do not form a full frame",
            residual,
            len(sse_lines),
        )
        return None
    return "".join(sse_lines)


def _decompress_b64_body(
    body_b64: str,
    content_encoding: Optional[str],
    content_type: Optional[str] = None,
) -> tuple[Optional[str], bool]:
    """Base64-decode, optionally decompress, and decode a body to text.

    Plain UTF-8 by default; gzip/deflate/Brotli via ``content_encoding``;
    AWS event-stream binary via ``content_type`` (see
    ``_parse_vnd_amazon_eventstream``). Returns ``(text, failed)``;
    ``text`` is None when ``failed``.
    """
    try:
        body_bytes = base64.b64decode(body_b64)
    except (binascii.Error, UnicodeDecodeError):
        return None, True

    if content_encoding:
        encoding = content_encoding.lower()
        if "gzip" in encoding:
            try:
                body_bytes = gzip.decompress(body_bytes)
            except (OSError, EOFError, zlib.error):
                # zlib.error: a valid gzip header wrapping a corrupt deflate
                # stream escapes the OSError/BadGzipFile paths.
                return None, True
        elif "deflate" in encoding:
            try:
                body_bytes = zlib.decompress(body_bytes)
            except (zlib.error, EOFError):
                return None, True
        elif "br" in encoding:
            import brotli

            try:
                body_bytes = brotli.decompress(body_bytes)
            except brotli.error:
                return None, True

    if content_type and _EVENTSTREAM_CONTENT_TYPE in content_type.lower():
        sse = _parse_vnd_amazon_eventstream(body_bytes)
        if sse is None:
            return None, True
        return sse, False

    try:
        return body_bytes.decode("utf-8"), False
    except UnicodeDecodeError:
        return None, True


@dataclass
class AwsCredentials:
    """AWS credentials: access keys, optional session token, expiration (UTC)."""

    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    expiration: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Validate credentials after initialization."""
        # Lazy import: models.py ships standalone to AWS Glue.
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
            dt = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            # ``expiration_str`` is customer-controlled (base64-JSON bearer
            # payload); don't log its content — log-injection vector.
            logger.warning("Could not parse credential expiration string")
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
    """Authorization payload containing AWS credentials and a secret ARN."""

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
        """Create an AuthPayload from a base64-encoded payload.

        The proxy removes the Bearer prefix first. The payload is a base64-encoded
        JSON string with "credentials" and "secret_arn" fields.

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
            # Never include raw_payload in the message: the base64 blob holds
            # temporary AWS credentials that would surface in error responses,
            # logs, and Envoy access logs. `from e` keeps the decode error for
            # debugging.
            msg = f"Failed to decode authorization payload: {type(e).__name__}"
            raise PayloadError(msg) from e


@dataclass
class PrincipalInfo:
    """Principal identity extracted from an AWS ARN.

    ``project`` is derived from ``UserProfile_`` roles.
    """

    arn: str = "unknown"
    account_id: str = "unknown"
    principal: Optional[str] = None
    session_name: Optional[str] = None
    project: Optional[str] = None

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
    """AWS SecretsManager payload for our proxy API keys.

    Each secret is either a plain string (the whole API key) or a JSON payload
    in this shape.
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
        except ValidationError:
            # Do NOT pass exc_info — pydantic ValidationError formats the
            # offending input verbatim, which here is the raw secret JSON
            # (upstream provider API key).
            logger.info("JSON secret with unrecognised schema, using JSON as API key")
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
    """Result of an authentication operation."""

    api_key: str
    signing_key: Optional[SigningKey]
    principal_info: PrincipalInfo

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


# Firehose record dataclasses - define the structure of published records


@dataclass
class MetadataRecord:
    """Per-request principal + secret identity record published to Firehose.

    ``timestamp`` is the canonical partition key for ETL.
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
        """Convert to dictionary for Firehose publishing."""
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
    """Request-headers audit record. ``raw_headers`` values are base64-encoded."""

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
        """Convert to dictionary for Firehose publishing."""
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
    """One chunk of a request body. ``body`` is base64; ETL concatenates by chunk_id.

    ``num_chunks=0`` is the per-chunk wire format where Glue derives the total
    at aggregation via ``count(*)``.

    ``dropped=True`` is a sentinel for a chunk the publish queue rejected under
    backpressure (``body``/``body_size`` empty/zero). ETL must treat a
    reassembled body with any sentinel as incomplete, not read chunk_id gaps as
    absence-of-data.

    ``truncated=True`` marks a chunk capped by an upstream safety limit
    (currently only the WS deflate decompression cap in ``frame_observer.py``):
    the bytes present are real but incomplete vs. the wire.

    ``final_chunk=True`` marks the terminal chunk of a streamed
    (``num_chunks=0``) ext_proc body (Envoy's ``end_of_stream``) — the explicit
    end-of-body marker the ``count(*)`` scheme otherwise lacks, so a lost
    *trailing* chunk (surviving ids stay contiguous and match the count) can be
    detected. The declared/buffered path stamps the real total per chunk and
    leaves this ``False``.
    """

    request_id: str
    body: str
    body_size: int
    timestamp: str
    chunk_id: int
    num_chunks: int
    published_at: str
    dropped: bool = False
    truncated: bool = False
    final_chunk: bool = False
    # Per-direction WS frame ordinal; None for HTTP bodies. Glue keys WS frames
    # by (request_id, frame_index) to reassemble and disambiguate frames.
    frame_index: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firehose publishing."""
        return {
            "record_type": "request_body",
            "request_id": self.request_id,
            "body": self.body,
            "body_size": self.body_size,
            "chunk_id": self.chunk_id,
            "num_chunks": self.num_chunks,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
            "dropped": self.dropped,
            "truncated": self.truncated,
            "final_chunk": self.final_chunk,
            "frame_index": self.frame_index,
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
            {"name": "dropped", "type": "boolean"},
            {"name": "truncated", "type": "boolean"},
            {"name": "final_chunk", "type": "boolean"},
            {"name": "frame_index", "type": "bigint"},
        ]


@dataclass
class RequestTrailersRecord:
    """Request-trailers audit record."""

    request_id: str
    trailers: Dict[str, str]
    timestamp: str
    published_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firehose publishing."""
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
    """Response-headers audit record. ``raw_headers`` values are base64-encoded."""

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
        """Convert to dictionary for Firehose publishing."""
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
    """One chunk of a response body. SSE/chunked streams emit one record per chunk.

    ``dropped`` / ``truncated`` / ``final_chunk`` semantics mirror
    :class:`RequestBodyRecord`.
    """

    request_id: str
    body: str
    body_size: int
    timestamp: str
    chunk_id: int
    num_chunks: int
    published_at: str
    dropped: bool = False
    truncated: bool = False
    final_chunk: bool = False
    # Per-direction WS frame ordinal; None for HTTP bodies. Glue keys WS frames
    # by (request_id, frame_index) to reassemble and disambiguate frames.
    frame_index: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firehose publishing."""
        return {
            "record_type": "response_body",
            "request_id": self.request_id,
            "body": self.body,
            "body_size": self.body_size,
            "chunk_id": self.chunk_id,
            "num_chunks": self.num_chunks,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
            "dropped": self.dropped,
            "truncated": self.truncated,
            "final_chunk": self.final_chunk,
            "frame_index": self.frame_index,
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
            {"name": "dropped", "type": "boolean"},
            {"name": "truncated", "type": "boolean"},
            {"name": "final_chunk", "type": "boolean"},
            {"name": "frame_index", "type": "bigint"},
        ]


@dataclass
class ResponseTrailersRecord:
    """Response-trailers audit record."""

    request_id: str
    trailers: Dict[str, str]
    timestamp: str
    published_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firehose publishing."""
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
class WSSummaryRecord:
    """Per-connection WebSocket summary emitted on stream end.

    A joinable, cheap view of connection-level shape (duration, frame
    counts per direction, close code) so analytics don't have to
    aggregate the body stream.
    """

    request_id: str
    timestamp: str
    published_at: str
    duration_seconds: float
    close_code: Optional[int] = None
    close_initiator: Optional[str] = None
    client_text_frames: int = 0
    client_binary_frames: int = 0
    client_ping_frames: int = 0
    client_pong_frames: int = 0
    client_close_frames: int = 0
    server_text_frames: int = 0
    server_binary_frames: int = 0
    server_ping_frames: int = 0
    server_pong_frames: int = 0
    server_close_frames: int = 0
    # Audit-integrity counters: frames lost to publish-queue backpressure or
    # capped by the deflate decompression limit. A cheap aggregate of the
    # per-frame ``dropped`` / ``truncated`` sentinels, joinable without
    # scanning the body stream.
    dropped_client_frames: int = 0
    dropped_server_frames: int = 0
    truncated_client_frames: int = 0
    truncated_server_frames: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firehose publishing."""
        return {
            "record_type": "ws_summary",
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "published_at": self.published_at,
            "duration_seconds": self.duration_seconds,
            "close_code": self.close_code,
            "close_initiator": self.close_initiator,
            "client_text_frames": self.client_text_frames,
            "client_binary_frames": self.client_binary_frames,
            "client_ping_frames": self.client_ping_frames,
            "client_pong_frames": self.client_pong_frames,
            "client_close_frames": self.client_close_frames,
            "server_text_frames": self.server_text_frames,
            "server_binary_frames": self.server_binary_frames,
            "server_ping_frames": self.server_ping_frames,
            "server_pong_frames": self.server_pong_frames,
            "server_close_frames": self.server_close_frames,
            "dropped_client_frames": self.dropped_client_frames,
            "dropped_server_frames": self.dropped_server_frames,
            "truncated_client_frames": self.truncated_client_frames,
            "truncated_server_frames": self.truncated_server_frames,
        }

    @classmethod
    def glue_schema(cls) -> List[Dict[str, str]]:
        """Return Glue table schema for this record type."""
        return [
            {"name": "record_type", "type": "string"},
            {"name": "request_id", "type": "string"},
            {"name": "timestamp", "type": "string"},
            {"name": "published_at", "type": "string"},
            {"name": "duration_seconds", "type": "double"},
            {"name": "close_code", "type": "int"},
            {"name": "close_initiator", "type": "string"},
            {"name": "client_text_frames", "type": "bigint"},
            {"name": "client_binary_frames", "type": "bigint"},
            {"name": "client_ping_frames", "type": "bigint"},
            {"name": "client_pong_frames", "type": "bigint"},
            {"name": "client_close_frames", "type": "bigint"},
            {"name": "server_text_frames", "type": "bigint"},
            {"name": "server_binary_frames", "type": "bigint"},
            {"name": "server_ping_frames", "type": "bigint"},
            {"name": "server_pong_frames", "type": "bigint"},
            {"name": "server_close_frames", "type": "bigint"},
            {"name": "dropped_client_frames", "type": "bigint"},
            {"name": "dropped_server_frames", "type": "bigint"},
            {"name": "truncated_client_frames", "type": "bigint"},
            {"name": "truncated_server_frames", "type": "bigint"},
        ]


@dataclass
class JoinedLogRecord:
    """Joined log record: output of the Glue ETL job (process_raw_data.py).

    INNER-joins all streams (metadata, request/response headers/body) by
    request_id, so only complete transactions appear. Schema is generated
    dynamically from the source schemas: metadata timestamp is the canonical
    (unprefixed) timestamp, other streams get ``<stream>_`` prefixes, internal
    fields (record_type, non-metadata published_at) are dropped, and ETL
    metadata (etl_processed_at, partition columns) is added.

    Limitations:
    - Incomplete transactions (missing any stream) are excluded.
    - Trailers are not included.
    - Responses arriving more than MINUTES_TO_PROCESS after the request may be
      filtered out, yielding incomplete transactions.

    Body data and raw header maps stay base64-encoded; individual header fields
    are decoded for convenience.
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
            self.request_body_body,
            self.request_headers_content_encoding,
            self.request_headers_content_type,
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
            self.response_body_body,
            self.response_headers_content_encoding,
            self.response_headers_content_type,
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
        """Return Glue partition key schema (columns derived from timestamp during ETL).

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

        Returns:
            List of partition column names
        """
        return [col["name"] for col in cls.partition_keys()]

    @classmethod
    def partition_path_from_datetime(cls, dt, zero_pad: bool = False) -> str:
        """Build an S3 partition path (year=/month=/day=/hour=) from a datetime.

        Padding differs by system and must match the writer:
        - Spark (OUTPUT, default): non-padded (month=4) — integer columns.
        - Kinesis Firehose (INPUT, zero_pad=True): zero-padded (month=04) —
          extracted from ISO timestamp strings.

        Args:
            dt: Datetime to extract partition values from
            zero_pad: Zero-pad month/day/hour to 2 digits (Firehose) if True;
                      else Spark's non-padded format (default).

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
        """Return Spark SQL expression to extract a partition column from timestamp.

        Args:
            column: Partition column name (year, month, day, hour)

        Returns:
            Spark SQL expression string
        """
        if column not in cls.partition_key_names():
            raise ValueError(f"Invalid partition column name: {column}")
        return f"{column}(timestamp)"
