"""
Short-lived upstream tokens minted from federation roles.

Minting has two independent parts:

1. Identity proof (:class:`StsFederationService`): with the caller's own
   credentials, assume the secret's federation role. For JWT providers that
   session then requests an STS web identity token, a signed JWT whose
   subject is the federation role and whose tags carry the caller's role name
   and project.
2. Exchange: trade the proof for a provider bearer token. Each provider gets
   its own adapter. :class:`AnthropicTokenExchange` posts the JWT to the
   provider's OAuth endpoint; :class:`GcpTokenExchange` has the session sign
   an AWS ``GetCallerIdentity`` request for Google STS and impersonates a
   service account with the result.

:class:`TokenMintService` sequences the two for a given secret type.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional, Sequence

import httpx
from aiobotocore.config import AioConfig
from aiobotocore.session import AioSession, get_session
from botocore.exceptions import ClientError
from google.auth import aws as google_aws
from google.auth import exceptions as google_exceptions
from google.auth import transport as google_transport
from google.auth.external_account import SupplierContext

from portunus.config import FederationConfig, config
from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
)
from portunus.models import (
    AnthropicWifSecret,
    AwsCredentials,
    GcpWorkloadIdentitySecret,
    MintSecretBase,
    PrincipalInfo,
)
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
FEDERATION_SESSION_SECONDS = 3600
# The identity token only has to outlive the exchange call. STS accepts
# 60-3600 s; a secret's token_duration_seconds may cap it further.
IDENTITY_TOKEN_SECONDS = 900
IDENTITY_TOKEN_SIGNING_ALGORITHM = "RS256"
AWS_SUBJECT_TOKEN_TYPE = "urn:ietf:params:aws:token-type:aws4_request"
GOOGLE_STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"
GOOGLE_IAM_CREDENTIALS_URL = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
    "{service_account}:generateAccessToken"
)

# IAM's character classes are ASCII; re.ASCII keeps \w from admitting more.
_IAM_ROLE_ARN = re.compile(
    r"^arn:aws:iam::(?P<account_id>\d{12}):role"
    r"(?P<path>/(?:[\w+=,.@-]+/)*)(?P<name>[\w+=,.@-]+)$",
    re.ASCII,
)
_ROLE_SESSION_NAME = re.compile(r"^[\w+=,.@-]{2,64}$", re.ASCII)
# /authorise has a 9 s budget (app.py). One attempt per STS call and a short
# exchange timeout keep a slow dependency from turning into proxy 503s.
_STS_CLIENT_CONFIG = AioConfig(
    connect_timeout=2,
    read_timeout=3,
    retries={"max_attempts": 1, "mode": "standard"},
)
_EXCHANGE_TIMEOUT = httpx.Timeout(4.0)


@dataclass(frozen=True)
class FederationIdentity:
    """An assumed federation-role session acting for one caller.

    Attributes:
        credentials: The federation session's credentials
        session_name: The caller's IAM role name (the session's RoleSessionName)
        project: The caller's project, or "" when unknown
    """

    credentials: AwsCredentials
    session_name: str
    project: str


@dataclass(frozen=True)
class WebIdentityToken:
    """STS-signed JWT proving a federation identity to a provider."""

    token: str
    expires_at: datetime


@dataclass(frozen=True)
class MintedToken:
    """A provider bearer token and when it stops being valid."""

    token: str
    expires_at: datetime


def validate_federation_role_arn(
    arn: str, allowed_account_ids: Sequence[str], role_path_prefix: str
) -> None:
    """Reject federation role ARNs outside the deployment's allowed set.

    Args:
        arn: The secret's ``federation_role_arn``
        allowed_account_ids: Accounts a federation role may live in
        role_path_prefix: IAM path the role must sit under

    Raises:
        AuthenticationError: Malformed ARN, account not allowed, or role path
            outside ``role_path_prefix``. Also when no accounts are allowed,
            which disables minting entirely.
    """
    if not allowed_account_ids:
        raise AuthenticationError(
            "Token minting is disabled: FEDERATION_ALLOWED_ACCOUNT_IDS is not set"
        )
    match = _IAM_ROLE_ARN.fullmatch(arn)
    if match is None:
        raise AuthenticationError("federation_role_arn is not an IAM role ARN")
    if match["account_id"] not in allowed_account_ids:
        raise AuthenticationError("federation_role_arn is not in an allowed account")
    if not match["path"].startswith(role_path_prefix):
        raise AuthenticationError(
            f"federation_role_arn is not under the {role_path_prefix} role path"
        )


def caller_role_name(principal: PrincipalInfo) -> str:
    """The caller's IAM role name, used as the federation RoleSessionName.

    Raises:
        CredentialsError: The caller is not an assumed role, or its role name
            is not a valid session name.
    """
    prefix = "assumed-role/"
    if not principal.principal or not principal.principal.startswith(prefix):
        raise CredentialsError("Token minting requires an assumed-role caller")
    name = principal.principal[len(prefix) :]
    if not _ROLE_SESSION_NAME.fullmatch(name):
        raise CredentialsError("Caller role name is not a valid session name")
    return name


def caller_project(principal: PrincipalInfo) -> str:
    """The caller's project for the session tag, or "" when unknown."""
    project = principal.project
    # parse_identity_from_arn() reports a missing project as "unknown".
    if project is None or project == "unknown":
        return ""
    return project


def _client_error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", ""))


class StsFederationService:
    """Identity-proof step: assume the federation role and issue STS JWTs.

    Both calls use a regional STS endpoint. GetWebIdentityToken is not served
    by the global endpoint, and a deployment's federation-role trust policy
    may pin the request to a specific VPC endpoint.
    """

    def __init__(
        self,
        boto_session: Optional[AioSession] = None,
        federation_config: Optional[FederationConfig] = None,
    ) -> None:
        self.boto_session = boto_session or get_session()
        self.federation_config = federation_config or config.federation

    def region(self) -> str:
        """The SDK's configured AWS region.

        Raises:
            ConfigurationError: No region configured.
        """
        region = self.boto_session.get_config_variable("region")
        if not region:
            raise ConfigurationError("AWS region is not configured")
        return str(region)

    def endpoint_url(self) -> str:
        """Resolve the STS endpoint for federation calls.

        Raises:
            ConfigurationError: No explicit endpoint and no region configured.
        """
        explicit = self.federation_config.sts_endpoint_url or config.aws.endpoint_url
        if explicit:
            return explicit
        return f"https://sts.{self.region()}.amazonaws.com"

    @capture_async()
    async def assume_federation_role(
        self, credentials: AwsCredentials, principal: PrincipalInfo, role_arn: str
    ) -> FederationIdentity:
        """Assume ``role_arn`` with the caller's credentials.

        Raises:
            CredentialsError: Caller credentials expired, or the caller is not
                an assumed role.
            AuthenticationError: STS refused the assumption.
        """
        session_name = caller_role_name(principal)
        try:
            async with self.boto_session.create_client(
                "sts",
                aws_access_key_id=credentials.access_key_id,
                aws_secret_access_key=credentials.secret_access_key,
                aws_session_token=credentials.session_token,
                endpoint_url=self.endpoint_url(),
                config=_STS_CLIENT_CONFIG,
            ) as sts:
                response = await sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=FEDERATION_SESSION_SECONDS,
                )
        except ClientError as e:
            code = _client_error_code(e)
            if code == "ExpiredToken":
                raise CredentialsError("AWS credentials have expired") from e
            logger.error(f"AssumeRole on federation role failed ({code}): {e}")
            raise AuthenticationError(
                f"Could not assume federation role ({code or 'unknown error'})"
            ) from e
        session = response["Credentials"]
        return FederationIdentity(
            credentials=AwsCredentials(
                access_key_id=session["AccessKeyId"],
                secret_access_key=session["SecretAccessKey"],
                session_token=session["SessionToken"],
                expiration=session["Expiration"],
            ),
            session_name=session_name,
            project=caller_project(principal),
        )

    @capture_async()
    async def web_identity_token(
        self, identity: FederationIdentity, audience: str, max_duration_seconds: int
    ) -> WebIdentityToken:
        """Issue a fresh STS-signed JWT for ``audience`` from the federation session.

        Providers treat the JWT ID as single-use, so callers must request a new
        token for every exchange rather than reuse one.

        Raises:
            AuthenticationError: STS refused to issue the token.
        """
        tags = [
            {
                "Key": self.federation_config.user_tag_key,
                "Value": identity.session_name,
            },
            {"Key": self.federation_config.project_tag_key, "Value": identity.project},
        ]
        try:
            async with self.boto_session.create_client(
                "sts",
                aws_access_key_id=identity.credentials.access_key_id,
                aws_secret_access_key=identity.credentials.secret_access_key,
                aws_session_token=identity.credentials.session_token,
                endpoint_url=self.endpoint_url(),
                config=_STS_CLIENT_CONFIG,
            ) as sts:
                response = await sts.get_web_identity_token(
                    Audience=[audience],
                    SigningAlgorithm=IDENTITY_TOKEN_SIGNING_ALGORITHM,
                    DurationSeconds=min(IDENTITY_TOKEN_SECONDS, max_duration_seconds),
                    Tags=tags,
                )
        except ClientError as e:
            code = _client_error_code(e)
            logger.error(f"GetWebIdentityToken failed ({code}): {e}")
            raise AuthenticationError(
                f"Could not issue identity token ({code or 'unknown error'})"
            ) from e
        return WebIdentityToken(
            token=response["WebIdentityToken"], expires_at=response["Expiration"]
        )


class AnthropicTokenExchange:
    """Exchange adapter for Anthropic's RFC 7523 JWT-bearer token endpoint."""

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None) -> None:
        self._http_client = http_client

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Shared client, created on first use so the pool outlives one call."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=_EXCHANGE_TIMEOUT)
        return self._http_client

    async def aclose(self) -> None:
        """Close the HTTP client, if one was created."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    @capture_async()
    async def exchange(self, assertion: str, secret: AnthropicWifSecret) -> MintedToken:
        """POST the JWT to ``https://<host>/v1/oauth/token``.

        Raises:
            AuthenticationError: Transport failure, non-200 response, or a
                response without ``access_token`` and ``expires_in``.
        """
        url = f"https://{secret.host}/v1/oauth/token"
        requested_at = datetime.now(timezone.utc)
        try:
            response = await self.http_client.post(
                url,
                json={
                    "grant_type": JWT_BEARER_GRANT_TYPE,
                    "assertion": assertion,
                    "federation_rule_id": secret.federation_rule_id,
                    "organization_id": secret.organization_id,
                    "service_account_id": secret.service_account_id,
                    "workspace_id": secret.workspace_id,
                },
            )
        except httpx.HTTPError as e:
            logger.error(
                f"Token exchange with {secret.host} failed: {type(e).__name__}: {e}"
            )
            raise AuthenticationError(
                f"Token exchange with {secret.host} failed"
            ) from e

        if response.status_code != 200:
            logger.error(
                f"Token exchange with {secret.host} returned HTTP "
                f"{response.status_code}: {response.text[:500]}"
            )
            raise AuthenticationError(
                f"Token exchange with {secret.host} returned "
                f"HTTP {response.status_code}"
            )

        try:
            body = response.json()
            token = body["access_token"]
            expires_in = int(body["expires_in"])
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Token exchange with {secret.host} returned a malformed body")
            raise AuthenticationError(
                f"Token exchange with {secret.host} returned a malformed response"
            ) from e
        if not isinstance(token, str) or not token:
            raise AuthenticationError(
                f"Token exchange with {secret.host} returned an empty token"
            )
        return MintedToken(
            token=token, expires_at=requested_at + timedelta(seconds=expires_in)
        )


class SessionCredentialsSupplier(google_aws.AwsSecurityCredentialsSupplier):
    """Hands one federation session's credentials to google-auth.

    google-auth's built-in supplier reads the process environment and the
    instance metadata service, neither of which holds the per-caller session.
    """

    def __init__(self, credentials: AwsCredentials, region: str) -> None:
        self._credentials = credentials
        self._region = region

    def get_aws_security_credentials(
        self, context: SupplierContext, request: google_transport.Request
    ) -> google_aws.AwsSecurityCredentials:
        return google_aws.AwsSecurityCredentials(
            access_key_id=self._credentials.access_key_id,
            secret_access_key=self._credentials.secret_access_key,
            session_token=self._credentials.session_token,
        )

    def get_aws_region(
        self, context: SupplierContext, request: google_transport.Request
    ) -> str:
        return self._region


class _HttpxResponse(google_transport.Response):
    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    @property
    def status(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> Mapping[str, str]:
        return self._response.headers

    @property
    def data(self) -> bytes:
        return self._response.content


class HttpxRequest(google_transport.Request):
    """google-auth transport over a synchronous httpx client."""

    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs: object,
    ) -> _HttpxResponse:
        if kwargs:
            raise google_exceptions.TransportError(
                f"Unsupported transport options: {sorted(kwargs)}"
            )
        try:
            response = self._client.request(
                method,
                url,
                content=body,
                headers=headers,
                timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
            )
        except httpx.HTTPError as e:
            raise google_exceptions.TransportError(e) from e
        return _HttpxResponse(response)


class GcpTokenExchange:
    """Exchange adapter for Google workload identity federation.

    google-auth does the exchange: it signs an AWS ``GetCallerIdentity``
    request with the federation session's credentials, trades it at Google
    STS for a federated token, and impersonates the service account with
    that. Its client is blocking, so each refresh runs in a worker thread.
    """

    def __init__(self, http_client: Optional[httpx.Client] = None) -> None:
        self._http_client = http_client

    @property
    def http_client(self) -> httpx.Client:
        """Shared client, created on first use so the pool outlives one call."""
        if self._http_client is None:
            self._http_client = httpx.Client(timeout=_EXCHANGE_TIMEOUT)
        return self._http_client

    async def aclose(self) -> None:
        """Close the HTTP client, if one was created."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    @capture_async()
    async def exchange(
        self,
        identity: FederationIdentity,
        region: str,
        secret: GcpWorkloadIdentitySecret,
    ) -> MintedToken:
        """Obtain an access token for ``secret.service_account``.

        Args:
            identity: The assumed federation-role session
            region: AWS region the signed ``GetCallerIdentity`` request names
            secret: The ``gcp_workload_identity`` secret

        Raises:
            AuthenticationError: Google STS or IAM Credentials refused, the
                transport failed, or no token came back.
        """
        credentials = google_aws.Credentials(
            audience=secret.audience,
            subject_token_type=AWS_SUBJECT_TOKEN_TYPE,
            token_url=GOOGLE_STS_TOKEN_URL,
            service_account_impersonation_url=GOOGLE_IAM_CREDENTIALS_URL.format(
                service_account=secret.service_account
            ),
            service_account_impersonation_options={
                "token_lifetime_seconds": secret.token_lifetime_seconds
            },
            scopes=secret.scopes,
            aws_security_credentials_supplier=SessionCredentialsSupplier(
                identity.credentials, region
            ),
        )
        try:
            await asyncio.to_thread(credentials.refresh, HttpxRequest(self.http_client))
        except google_exceptions.GoogleAuthError as e:
            logger.error(
                f"Google token exchange for {secret.service_account} failed: "
                f"{type(e).__name__}: {str(e)[:500]}"
            )
            raise AuthenticationError(
                f"Google token exchange for {secret.service_account} failed"
            ) from e

        token = credentials.token
        expiry = credentials.expiry
        if not isinstance(token, str) or not token or not isinstance(expiry, datetime):
            raise AuthenticationError(
                f"Google token exchange for {secret.service_account} returned no token"
            )
        # google-auth expiries are naive UTC datetimes.
        return MintedToken(token=token, expires_at=expiry.replace(tzinfo=timezone.utc))


class TokenMintService:
    """Mint an upstream token for a secret that describes how to obtain one."""

    def __init__(
        self,
        sts: Optional[StsFederationService] = None,
        anthropic: Optional[AnthropicTokenExchange] = None,
        gcp: Optional[GcpTokenExchange] = None,
        federation_config: Optional[FederationConfig] = None,
    ) -> None:
        self.federation_config = federation_config or config.federation
        self.sts = sts or StsFederationService(federation_config=self.federation_config)
        self.anthropic = anthropic or AnthropicTokenExchange()
        self.gcp = gcp or GcpTokenExchange()

    async def aclose(self) -> None:
        """Release adapter resources."""
        await self.anthropic.aclose()
        await self.gcp.aclose()

    @capture_async()
    async def mint(
        self,
        credentials: AwsCredentials,
        principal: PrincipalInfo,
        secret: MintSecretBase,
    ) -> MintedToken:
        """Validate the federation role, prove the caller's identity, and exchange.

        Raises:
            AuthenticationError: Role not allowed, STS refused, or the
                exchange failed.
            CredentialsError: Caller credentials expired or not an assumed role.
            ConfigurationError: A ``gcp_workload_identity`` secret with no AWS
                region configured.
        """
        validate_federation_role_arn(
            secret.federation_role_arn,
            self.federation_config.allowed_account_ids,
            self.federation_config.role_path_prefix,
        )
        if isinstance(secret, AnthropicWifSecret):
            identity = await self.sts.assume_federation_role(
                credentials, principal, secret.federation_role_arn
            )
            proof = await self.sts.web_identity_token(
                identity, secret.audience, secret.token_duration_seconds
            )
            return await self.anthropic.exchange(proof.token, secret)
        if isinstance(secret, GcpWorkloadIdentitySecret):
            region = self.sts.region()
            identity = await self.sts.assume_federation_role(
                credentials, principal, secret.federation_role_arn
            )
            return await self.gcp.exchange(identity, region, secret)
        raise AuthenticationError(
            f"No token exchange for secret type {type(secret).__name__}"
        )
