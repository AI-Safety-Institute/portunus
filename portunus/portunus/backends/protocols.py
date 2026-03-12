"""Protocol definitions for pluggable Portunus backends.

These protocols define the contracts that backend implementations must satisfy.
Auth and publishing backends are independently configurable, allowing mixing
of different providers (e.g. AWS auth with a non-Kinesis publisher).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from portunus.models import AuthResult


@runtime_checkable
class AuthBackend(Protocol):
    """Resolves caller identity and fetches API key secrets from an opaque auth payload.

    Implementations handle payload parsing, identity resolution, secret
    retrieval, and optional request signing. The raw_payload is an opaque
    string whose format is defined by the backend (e.g. base64-encoded JSON
    with AWS credentials for the AWS backend).
    """

    async def authenticate(
        self,
        raw_payload: str,
        request_id: str,
        target_host: str | None = None,
    ) -> AuthResult:
        """Decode payload, verify caller identity, fetch API key secret.

        Args:
            raw_payload: Opaque auth payload from the proxy.
            request_id: Request ID for logging/tracing.
            target_host: Optional target host for secret validation.

        Returns:
            AuthResult with api_key, optional signing_key, and principal_info.

        Raises:
            PayloadError: If the payload cannot be decoded.
            CredentialsError: If credentials are invalid or expired.
            AuthenticationError: If authentication fails.
            FetchSecretError: If the secret cannot be retrieved.
        """
        ...

    async def sign_request(
        self,
        raw_payload: str,
        signable_request: Any,
        auth_result: AuthResult,
    ) -> dict[str, str] | None:
        """Optionally sign a request using backend-specific signing mechanisms.

        Args:
            raw_payload: Same opaque payload used for authenticate().
            signable_request: Request details needed for signature generation.
            auth_result: The result from authenticate() (contains signing_key).

        Returns:
            Dict with signature headers, or None if signing is not supported
            or not required for this request.
        """
        ...


@runtime_checkable
class StreamPublisher(Protocol):
    """Publishes a record to a named stream.

    Implementations handle the transport layer (Kinesis, Pub/Sub, stdout, etc.).
    Record construction (MetadataRecord, RequestHeadersRecord, etc.) stays in
    PublishService as business logic.
    """

    async def publish(
        self,
        stream_name: str,
        record_data: dict[str, Any],
        partition_key: str,
    ) -> bool:
        """Publish a single record to the named stream.

        Args:
            stream_name: Logical stream name (e.g. from config).
            record_data: Serializable record data dict.
            partition_key: Key for partitioning (typically request_id).

        Returns:
            True if published successfully, False if skipped
            (e.g. stream not configured).

        Raises:
            ServiceError: If publishing fails.
        """
        ...
