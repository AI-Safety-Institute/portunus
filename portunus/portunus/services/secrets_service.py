"""
Secrets management service module.

This module contains the SecretsService class, which is responsible for
interacting with AWS Secrets Manager to retrieve API keys and other secrets.
"""

import logging

from aiobotocore.session import get_session

from portunus.config import config
from portunus.exceptions import FetchSecretError
from portunus.models import AuthPayload
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")


class SecretsService:
    """
    Service for managing AWS Secrets Manager interactions.

    This service is responsible for retrieving secrets from AWS Secrets Manager,
    including API keys.
    """

    def __init__(self, boto_session=None):
        """Initialize the SecretsService.

        Args:
            boto_session: Optional aiobotocore session. Defaults to
                ``get_session()``; tests pass a fake to avoid real AWS.
        """
        self.boto_session = boto_session if boto_session is not None else get_session()

    @capture_async()
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
            # Customer supplies ``secret_arn``; boto echoes it into the
            # exception message. Logging that verbatim is a log-injection
            # vector (newlines in the supplied string fake CloudWatch
            # records) and a cross-account ARN-disclosure channel. Log
            # only the exception class.
            logger.error(
                "Failed to get secret from Secrets Manager: %s", type(e).__name__
            )
            raise FetchSecretError(403, "Failed to retrieve API key secret") from e
