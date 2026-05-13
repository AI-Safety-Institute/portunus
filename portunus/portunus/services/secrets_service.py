"""
Secrets management service module.

This module contains the SecretsService class, which is responsible for
interacting with AWS Secrets Manager to retrieve API keys and other secrets.
"""

import logging

from aiobotocore.session import get_session
from aws_xray_sdk.core import xray_recorder

from portunus.config import config
from portunus.exceptions import FetchSecretError
from portunus.models import AuthPayload

logger = logging.getLogger("api.access")


class SecretsService:
    """
    Service for managing AWS Secrets Manager interactions.

    This service is responsible for retrieving secrets from AWS Secrets Manager,
    including API keys.
    """

    def __init__(self):
        """Initialize the SecretsService."""
        self.boto_session = get_session()

    @xray_recorder.capture_async()  # type: ignore
    async def fetch_secret(self, payload: AuthPayload) -> str:
        """
        Fetch raw secret from Secrets Manager.

        Args:
            payload: An object containing AWS credentials and secret ARN

        Returns:
            The raw secret string retrieved from Secrets Manager

        Raises:
            FetchSecretError: If there's an error retrieving the secret
        """
        try:
            async with self.boto_session.create_client(
                "secretsmanager",
                aws_access_key_id=payload.credentials.access_key_id,
                aws_secret_access_key=payload.credentials.secret_access_key,
                aws_session_token=payload.credentials.session_token,
                endpoint_url=config.aws.endpoint_url,
            ) as client:
                response = await client.get_secret_value(SecretId=payload.secret_arn)
                return response["SecretString"]
        except Exception as e:
            # Log the full boto3 error server-side for diagnostics — it
            # carries the AWS request id, the offending Resource ARN, and
            # the principal ARN from cross-account denials. Don't echo
            # any of that back to the client: a client that supplied a
            # guessed ``secret_arn`` could distinguish "not found" from
            # "exists but denied", enumerating the account's secret
            # topology one probe at a time.
            logger.error(f"Failed to get secret from Secrets Manager: {e}")
            raise FetchSecretError(403, "Failed to retrieve API key secret") from e
