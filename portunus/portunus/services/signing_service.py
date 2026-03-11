import base64
import hashlib
import logging
from collections import OrderedDict
from datetime import datetime
from typing import TYPE_CHECKING, Literal, TypedDict

import boto3
from botocore.exceptions import ClientError
from pydantic import BaseModel, HttpUrl

from portunus.config import config
from portunus.exceptions import CredentialsError
from portunus.models import AwsCredentials, SigningKey

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient


class SignableRequest(BaseModel):
    """Request model for signature generation.

    Attributes:
        url: Full URL of the request to be signed.
             If the sent request is different in any way, including query or hash
             parameters, the signature will be rejected.
        method: HTTP method of the request to be signed
        content_type: Content-Type of the request body
        content_digest: Digest of the request body
    """

    type: Literal["anthropic"]
    url: HttpUrl
    method: str
    content_type: str
    content_digest: str


SignatureHeaders = TypedDict(
    "SignatureHeaders",
    {
        "Signature-Input": str,
        "Signature": str,
    },
)


def _get_region_from_arn(arn: str) -> str:
    """Extract the region from an AWS ARN.

    ARN format: arn:aws:service:region:account:resource

    Args:
        arn: An AWS ARN string

    Returns:
        The region component of the ARN
    """
    parts = arn.split(":")
    return parts[3]


def sign_request(
    req: SignableRequest,
    signing_key: SigningKey,
    api_key: str,
    user_credentials: AwsCredentials,
) -> SignatureHeaders:
    """
    Sign an API request using AWS KMS according to RFC 9421 (HTTP Message Signatures).

    Args:
        req: request details used to create the signature
        signing_key: The signing key for this api key.
        api_key: The provider API key
        user_credentials: User's AWS credentials to use for KMS signing.

    Returns:
        Dictionary containing RFC 9421 compliant signature headers:
        - "Signature-Input": Metadata about the signature
        - "Signature": The actual signature

    Raises:
        CredentialsError: If the user's AWS credentials are invalid or expired
    """
    # RFC 9421 signature base
    created: int = int(datetime.now().timestamp())
    algorithm: str = "ecdsa-p256-sha256"

    signature_params, signature_base = _build_signature_params_and_base(
        req, signing_key, api_key, created, algorithm
    )

    kms: KMSClient = boto3.client(
        "kms",
        region_name=_get_region_from_arn(signing_key.kms_key_arn),
        aws_access_key_id=user_credentials.access_key_id,
        aws_secret_access_key=user_credentials.secret_access_key,
        aws_session_token=user_credentials.session_token,
        # Add endpoint_url if configured (for LocalStack)
        endpoint_url=config.aws.endpoint_url,
    )

    # Error codes that indicate credential issues
    # https://docs.aws.amazon.com/kms/latest/APIReference/CommonErrors.html
    credential_error_codes = {
        "ExpiredToken",
        "ExpiredTokenException",
        "AccessDeniedException",
        "NotAuthorized",
        "InvalidClientTokenId",
    }

    try:
        response = kms.sign(
            KeyId=signing_key.kms_key_arn,
            Message=hashlib.sha256(signature_base).digest(),
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        logging.error(
            f"KMS sign operation failed: {error_code}",
            exc_info=e,
            extra={
                "kms_key_arn": signing_key.kms_key_arn,
                "provider_id": signing_key.provider_id,
            },
        )
        if error_code in credential_error_codes:
            raise CredentialsError("AWS credentials are invalid or expired") from e
        raise

    signature_b64: str = base64.b64encode(response["Signature"]).decode()
    signature_name = "sig1"
    return {
        "Signature-Input": f"{signature_name}={signature_params}",
        "Signature": f"{signature_name}=:{signature_b64}:",
    }


def _build_signature_params_and_base(
    req: SignableRequest,
    signing_key: SigningKey,
    api_key: str,
    created: int,
    algorithm: str,
) -> tuple[str, bytes]:
    # OrderedDict to ensure the signing order and the signature parameters order match
    covered_components: OrderedDict[str, str] = OrderedDict()
    covered_components["@method"] = req.method
    covered_components["@target-uri"] = str(req.url)
    covered_components["content-digest"] = req.content_digest
    covered_components["content-type"] = req.content_type
    covered_components["x-api-key"] = api_key

    signature_params = ";".join(
        [
            f"({' '.join([f'"{k}"' for k in covered_components.keys()])})",
            f"created={created}",
            f'keyid="{signing_key.provider_id}"',
            f'alg="{algorithm}"',
        ]
    )

    components: list[str] = [
        *(f'"{k}": {v}' for k, v in covered_components.items()),
        f'"@signature-params": {signature_params}',
    ]
    signature_base: bytes = "\n".join(components).encode("ascii")

    return signature_params, signature_base
