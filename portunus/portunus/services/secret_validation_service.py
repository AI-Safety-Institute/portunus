"""
Validation service module.

Parses Secrets Manager secret strings into typed secrets and enforces target
host validation.
"""

import json
import logging
from typing import Optional

from pydantic import TypeAdapter, ValidationError

from portunus.exceptions import AuthenticationError
from portunus.models import (
    MintSecretBase,
    SecretsManagerAuthPayload,
    SecretsManagerSecret,
    SigningKey,
    TypedSecret,
)

logger = logging.getLogger("api.access")

_typed_secret: TypeAdapter[SecretsManagerSecret] = TypeAdapter(TypedSecret)


def parse_secret(secret_string: str) -> SecretsManagerSecret:
    """Parse a raw Secrets Manager value into a typed secret.

    Plaintext, non-object JSON, and JSON objects without a ``type`` that do not
    match the static schema are used verbatim as the API key, as they always
    have been. A JSON object with a ``type`` must validate as that type: a
    misconfigured mint secret raises rather than being forwarded upstream as a
    credential.

    Raises:
        AuthenticationError: ``type`` is unknown or its fields are invalid.
    """
    try:
        data = json.loads(secret_string)
    except json.JSONDecodeError:
        logger.info("Secret is plaintext format")
        return SecretsManagerAuthPayload(api_key=secret_string)

    if not isinstance(data, dict) or "type" not in data:
        try:
            return SecretsManagerAuthPayload.model_validate(data)
        except ValidationError as e:
            logger.info(
                "JSON secret with unrecognised schema, using JSON as API key",
                exc_info=e,
            )
            return SecretsManagerAuthPayload(api_key=secret_string)

    try:
        return _typed_secret.validate_python(data)
    except ValidationError as e:
        logger.error(f"Secret of type {data.get('type')!r} failed validation: {e}")
        raise AuthenticationError(
            "Secret has an unsupported type or invalid fields"
        ) from e


class SecretValidationService:
    """
    Service for validating secrets and extracting API keys.

    This service handles parsing secret formats and enforcing target host
    validation when required.
    """

    def validate_secret(
        self, secret_string: str, target_host: Optional[str]
    ) -> SecretsManagerSecret:
        """
        Parse the secret and enforce its host restriction, if it has one.

        Args:
            secret_string: Raw secret value from AWS Secrets Manager
            target_host: Expected target host from proxy (optional)

        Returns:
            The typed secret: a stored key or a mint description.

        Raises:
            AuthenticationError: Host mismatch, host restriction without a
                known target, or an invalid typed secret.
        """
        secret = parse_secret(secret_string)

        # If secret has host field, validation is required
        if secret.host:
            if not target_host:
                logger.warning(
                    f"Secret has host ({secret.host}) but proxy sent no target"
                )
                raise AuthenticationError(
                    "API key has host restriction but target host unknown"
                )
            if target_host != secret.host:
                logger.warning(
                    f"Host mismatch: proxy={target_host}, secret={secret.host}"
                )
                raise AuthenticationError("API key is not valid for target host")
            logger.info(f"Target host validation passed for {target_host}")
        else:
            logger.info("Secret has no host restriction, skipping validation")

        return secret

    def validate_and_extract_api_key(
        self, secret_string: str, target_host: str | None
    ) -> tuple[str, Optional[SigningKey]]:
        """
        Stored-key form of ``validate_secret``.

        Returns:
            The API key & signing key (optional) to use.

        Raises:
            AuthenticationError: As ``validate_secret``, or when the secret
                describes a token to mint rather than a stored key.
        """
        secret = self.validate_secret(secret_string, target_host)
        if isinstance(secret, MintSecretBase):
            raise AuthenticationError("Secret requires token minting")
        return secret.api_key, secret.signing_key
