import asyncio
import base64
import functools
import hashlib
import logging
import weakref
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import TYPE_CHECKING, Callable, Literal, Optional, TypedDict

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


class SigningOverloadedError(Exception):
    """Raised when the signing concurrency cap stayed saturated too long.

    Callers should fail closed (deny the request — ideally 503) rather than
    queue further: each waiting signing request pins its buffered body (up
    to 32 MiB, Envoy ``with_request_body``) in memory, so shedding promptly
    is what keeps a signing burst from exhausting memory.
    """


def _signing_settings() -> tuple[int, int, float]:
    """Resolve (executor_workers, max_concurrent, acquire_timeout_s).

    A single seam over ``config.signing`` so tests can patch the sizing
    in one place.
    """
    signing_cfg = config.signing
    return (
        signing_cfg.kms_executor_workers,
        signing_cfg.max_concurrent,
        signing_cfg.acquire_timeout_s,
    )


# Dedicated executor for KMS.Sign so signing throughput is bounded by an
# explicit knob, not the process-default ``asyncio.to_thread`` pool
# (~min(32, cpu+4) threads shared with every other to_thread user): with a
# slow KMS tail, signing bursts queue behind that tiny shared pool and
# stack latency toward the 15s ext_authz signing timeout (customer 504s).
# Threads are process-wide; the semaphore below is per event loop.
_kms_executor: Optional[ThreadPoolExecutor] = None
_signing_semaphores: (
    "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]"
) = weakref.WeakKeyDictionary()


def _get_kms_executor() -> ThreadPoolExecutor:
    global _kms_executor
    if _kms_executor is None:
        workers, _, _ = _signing_settings()
        _kms_executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="kms-sign"
        )
    return _kms_executor


def _get_signing_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    semaphore = _signing_semaphores.get(loop)
    if semaphore is None:
        _, max_concurrent, _ = _signing_settings()
        semaphore = asyncio.Semaphore(max_concurrent)
        _signing_semaphores[loop] = semaphore
    return semaphore


def reset_signing_runtime(*, wait: bool = False) -> None:
    """Tear down the KMS executor + semaphores (shutdown / test isolation)."""
    global _kms_executor
    if _kms_executor is not None:
        _kms_executor.shutdown(wait=wait, cancel_futures=True)
        _kms_executor = None
    _signing_semaphores.clear()


async def sign_request_async(
    req: "SignableRequest",
    signing_key: SigningKey,
    api_key: str,
    user_credentials: AwsCredentials,
    *,
    sign_fn: Optional[Callable[..., SignatureHeaders]] = None,
) -> SignatureHeaders:
    """Bounded, off-loop signing: the async entrypoint for the signing pass.

    Wraps a synchronous signer (:func:`sign_request` by default; servicer
    tests inject fakes via ``sign_fn``) with the two bounds a signing burst
    needs:

    1. A per-event-loop semaphore capping concurrent signing requests.
       Waiters that can't acquire within the timeout are shed with
       :class:`SigningOverloadedError` (fail closed) instead of piling up —
       each waiter pins its buffered request body (32 MiB Envoy buffer +
       the CheckRequest copy here), so unbounded waiting is a memory
       exhaustion vector.
    2. A dedicated ``ThreadPoolExecutor`` for the blocking KMS round-trip,
       so signing throughput is sized explicitly rather than by the shared
       process-default pool.

    Raises:
        SigningOverloadedError: concurrency cap saturated for longer than
            the acquire timeout; the caller must deny the request.
    """
    signer = sign_fn if sign_fn is not None else sign_request
    _, _, acquire_timeout = _signing_settings()
    semaphore = _get_signing_semaphore()
    try:
        async with asyncio.timeout(acquire_timeout):
            await semaphore.acquire()
    except TimeoutError:
        raise SigningOverloadedError(
            "Signing concurrency cap saturated; shedding request"
        ) from None
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _get_kms_executor(),
            functools.partial(signer, req, signing_key, api_key, user_credentials),
        )
    finally:
        semaphore.release()


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
            "KMS sign operation failed: %s",
            error_code or type(e).__name__,
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
