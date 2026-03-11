"""
Validation service module.

This module contains the ValidationService class, which is responsible for
validating secrets and extracting API keys with target host validation.
"""

import logging
from typing import Optional

from portunus.exceptions import AuthenticationError
from portunus.models import SecretsManagerAuthPayload, SigningKey

logger = logging.getLogger("api.access")


class SecretValidationService:
    """
    Service for validating secrets and extracting API keys.

    This service handles parsing secret formats and enforcing target host
    validation when required.
    """

    def validate_and_extract_api_key(
        self, secret_string: str, target_host: str | None
    ) -> tuple[str, Optional[SigningKey]]:
        """
        Parse secret and validate target host if secret is in JSON format.

        Args:
            secret_string: Raw secret value from AWS Secrets Manager
            target_host: Expected target host from proxy (optional)

        Returns:
            The API key & signing key (optional) to use.
            Only certain labs + models require a signing key, most are api-key-only

        Raises:
            AuthenticationError: If validation fails for JSON secrets with host field
        """
        secret = SecretsManagerAuthPayload.from_string(secret_string)

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

        return secret.api_key, secret.signing_key
