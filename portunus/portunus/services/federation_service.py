"""
Short-lived upstream tokens minted from federation roles.

Minting has two independent parts:

1. Identity proof (:class:`StsFederationService`): with the caller's own
   credentials, assume the secret's federation role, then prove that session's
   identity in the form the provider verifies. Either an STS web identity
   token (a signed JWT whose subject is the federation role and whose tags
   carry the user, the caller's role name, its session name and the project),
   or a SigV4-signed ``GetCallerIdentity`` request that the provider replays
   against AWS.
2. Exchange: trade the proof for a provider bearer token. Each provider has an
   adapter with the same ``exchange(proof, secret)`` shape.
   :class:`AnthropicTokenExchange` posts the JWT to the provider's OAuth
   endpoint; :class:`GcpTokenExchange` trades the signed request at Google STS
   and impersonates a service account with the result.

:class:`TokenMintService` pairs each secret type with its proof and adapter.
"""

import asyncio
import json
import logging
import re
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Protocol, Sequence

import httpx
from aiobotocore.config import AioConfig
from aiobotocore.session import AioSession, get_session
from botocore.exceptions import BotoCoreError, ClientError
from google.auth import aws as google_aws

from portunus.config import FederationConfig, config
from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
    UpstreamServiceError,
)
from portunus.models import (
    AnthropicWifSecret,
    AwsCredentials,
    GcpWifSecret,
    MintSecretBase,
    PrincipalInfo,
)
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# The identity token only has to outlive the exchange call. The session must
# outlive the token by more than the call latency: GetWebIdentityToken
# rejects a DurationSeconds longer than the session's remaining lifetime
# (SessionDurationEscalationException), so a 900 s session cannot issue a
# 900 s token.
FEDERATION_SESSION_SECONDS = 3600
IDENTITY_TOKEN_SECONDS = 900
IDENTITY_TOKEN_SIGNING_ALGORITHM = "RS256"
AWS_SUBJECT_TOKEN_TYPE = "urn:ietf:params:aws:token-type:aws4_request"
# Google replays the signed request here; it must be the regional endpoint.
AWS_GET_CALLER_IDENTITY_URL = (
    "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
)
GOOGLE_STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"
GOOGLE_TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
GOOGLE_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
# The only scope the federated token needs: calling generateAccessToken.
GOOGLE_IAM_SCOPE = "https://www.googleapis.com/auth/iam"
GOOGLE_IAM_CREDENTIALS_URL = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
    "{service_account}:generateAccessToken"
)

# IAM's character classes are ASCII; re.ASCII keeps \w from admitting more.
# A path segment is IAM's path charset (printable ASCII) minus the "/"
# separator; a role name is IAM's role-name charset, at most 64 characters.
_IAM_PATH_SEGMENT = r"[!-.0-~]+"
_IAM_ROLE_ARN = re.compile(
    r"^arn:aws:iam::(?P<account_id>\d{12}):role"
    rf"(?P<path>/(?:{_IAM_PATH_SEGMENT}/)*)(?P<name>[\w+=,.@-]{{1,64}})$",
    re.ASCII,
)
_ROLE_SESSION_NAME = re.compile(r"^[\w+=,.@-]{2,64}$", re.ASCII)
# STS tag values are [\p{L}\p{Z}\p{N}_.:/=+\-@]*. Role names, session names
# and source identities may also contain ",", so a valid one is not always a
# valid tag value.
_SESSION_TAG_VALUE = re.compile(r"^[\w .:/=+\-@]*$")
# /authorise has a 9 s budget (app.py), and the caller's identity check and
# secret fetch run before minting starts. The per-call limits below add up to
# more than that, so mint() also has an overall deadline.
MINT_DEADLINE_SECONDS = 6
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
        user: The caller's STS source identity, or its IAM role name when its
            session carries none
        principal: The caller's IAM role name (also the federation session's
            RoleSessionName)
        session: The caller's own RoleSessionName
        project: The caller's project, or "" when unknown
    """

    credentials: AwsCredentials
    user: str
    principal: str
    session: str
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

    An accepted ARN is ``arn:aws:iam::<account>:role<prefix><name>`` where
    ``<account>`` is allowed, ``<prefix>`` is ``role_path_prefix`` and
    ``<name>`` is any further IAM path plus a role name.

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
    """The caller's IAM role name: the principal tag and federation RoleSessionName.

    Raises:
        CredentialsError: The caller is not an assumed role, or its role name
            is not usable as a session name and tag value.
    """
    prefix = "assumed-role/"
    if not principal.principal or not principal.principal.startswith(prefix):
        raise CredentialsError("Token minting requires an assumed-role caller")
    name = principal.principal[len(prefix) :]
    if not _ROLE_SESSION_NAME.fullmatch(name):
        raise CredentialsError("Caller role name is not a valid session name")
    if not _SESSION_TAG_VALUE.fullmatch(name):
        raise CredentialsError("Caller role name cannot be used as a session tag")
    return name


def caller_session(principal: PrincipalInfo) -> str:
    """The caller's own RoleSessionName: the session tag.

    Raises:
        CredentialsError: The caller is not an assumed role, or its session
            name is not usable as a tag value.
    """
    if not principal.session_name:
        raise CredentialsError("Token minting requires an assumed-role caller")
    if not _SESSION_TAG_VALUE.fullmatch(principal.session_name):
        raise CredentialsError("Caller session name cannot be used as a session tag")
    return principal.session_name


def caller_user(role_name: str, source_identity: Optional[str]) -> str:
    """The user tag: the caller's STS source identity, else its IAM role name.

    Raises:
        CredentialsError: The source identity is not usable as a tag value.
    """
    if not source_identity:
        return role_name
    if not _SESSION_TAG_VALUE.fullmatch(source_identity):
        raise CredentialsError("Caller source identity cannot be used as a session tag")
    return source_identity


def caller_project(principal: PrincipalInfo) -> str:
    """The caller's project for the session tag, or "" when unknown.

    Raises:
        CredentialsError: The project is not usable as a tag value.
    """
    project = principal.project
    # parse_identity_from_arn() reports a missing project as "unknown".
    if project is None or project == "unknown":
        return ""
    if not _SESSION_TAG_VALUE.fullmatch(project):
        raise CredentialsError("Caller project cannot be used as a session tag")
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
            CredentialsError: Caller credentials expired, the caller has no
                session name, or its role name, session name, source identity
                or project cannot be used as a session tag.
            AuthenticationError: STS refused the assumption.
            UpstreamServiceError: STS could not be reached.
        """
        role_name = caller_role_name(principal)
        session = caller_session(principal)
        project = caller_project(principal)
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
                    RoleSessionName=role_name,
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
        except BotoCoreError as e:
            logger.error(
                f"AssumeRole on federation role failed: {type(e).__name__}: {e}"
            )
            raise UpstreamServiceError("STS is unavailable") from e
        issued = response["Credentials"]
        return FederationIdentity(
            credentials=AwsCredentials(
                access_key_id=issued["AccessKeyId"],
                secret_access_key=issued["SecretAccessKey"],
                session_token=issued["SessionToken"],
                expiration=issued["Expiration"],
            ),
            user=caller_user(role_name, response.get("SourceIdentity")),
            principal=role_name,
            session=session,
            project=project,
        )

    @capture_async()
    async def web_identity_token(
        self, identity: FederationIdentity, audience: str
    ) -> WebIdentityToken:
        """Issue a fresh STS-signed JWT for ``audience`` from the federation session.

        Providers treat the JWT ID as single-use, so callers must request a new
        token for every exchange rather than reuse one.

        Raises:
            AuthenticationError: STS refused to issue the token.
            UpstreamServiceError: STS could not be reached.
        """
        tags = [
            {"Key": self.federation_config.user_tag_key, "Value": identity.user},
            {
                "Key": self.federation_config.principal_tag_key,
                "Value": identity.principal,
            },
            {"Key": self.federation_config.session_tag_key, "Value": identity.session},
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
                    DurationSeconds=IDENTITY_TOKEN_SECONDS,
                    Tags=tags,
                )
        except ClientError as e:
            code = _client_error_code(e)
            logger.error(f"GetWebIdentityToken failed ({code}): {e}")
            raise AuthenticationError(
                f"Could not issue identity token ({code or 'unknown error'})"
            ) from e
        except BotoCoreError as e:
            logger.error(f"GetWebIdentityToken failed: {type(e).__name__}: {e}")
            raise UpstreamServiceError("STS is unavailable") from e
        return WebIdentityToken(
            token=response["WebIdentityToken"], expires_at=response["Expiration"]
        )

    @capture_async()
    async def signed_caller_identity(
        self, identity: FederationIdentity, audience: str
    ) -> str:
        """Sign a ``GetCallerIdentity`` request as proof of the federation identity.

        The provider replays the request against the regional STS endpoint, so
        the region comes from the SDK configuration rather than
        ``endpoint_url()``, which may name a VPC endpoint. The result is
        Google's ``aws4_request`` subject token: a URL-encoded JSON object with
        ``url``, ``method`` and a ``headers`` list.
        https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token

        Args:
            identity: The assumed federation-role session
            audience: The provider's workload identity pool provider resource
                name, bound to the request through a signed header

        Raises:
            ConfigurationError: No AWS region configured.
        """
        region = self.region()
        credentials = identity.credentials
        signed = google_aws.RequestSigner(region).get_request_options(
            google_aws.AwsSecurityCredentials(
                access_key_id=credentials.access_key_id,
                secret_access_key=credentials.secret_access_key,
                session_token=credentials.session_token,
            ),
            AWS_GET_CALLER_IDENTITY_URL.format(region=region),
            "POST",
            # Signed, so the request cannot be presented for another provider.
            additional_headers={"x-goog-cloud-target-resource": audience},
        )
        return urllib.parse.quote(
            json.dumps(
                {
                    "url": signed["url"],
                    "method": signed["method"],
                    "headers": [
                        {"key": key, "value": value}
                        for key, value in signed["headers"].items()
                    ],
                }
            )
        )


class _HttpTokenExchange:
    """Shared HTTP client and response handling for exchange adapters.

    Subclasses implement ``exchange(proof, secret)`` for their secret type
    and may override ``timeout``.
    """

    timeout: httpx.Timeout = _EXCHANGE_TIMEOUT

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None) -> None:
        self._http_client = http_client

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Shared client, created on first use so the pool outlives one call."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self._http_client

    async def aclose(self) -> None:
        """Close the HTTP client, if one was created."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _post_json(
        self,
        step: str,
        url: str,
        *,
        data: Optional[dict[str, str]] = None,
        json_body: Optional[dict[str, object]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, object]:
        """POST a form or JSON body and return the JSON object in a 200 response.

        ``step`` names the call in messages and logs, which carry the response
        status and (truncated) body but never the request.

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response.
            AuthenticationError: Any other non-200 response, or a body that is
                not a JSON object.
        """
        try:
            response = await self.http_client.post(
                url, data=data, json=json_body, headers=headers
            )
        except httpx.HTTPError as e:
            logger.error(f"{step} failed: {type(e).__name__}: {e}")
            raise UpstreamServiceError(f"{step} is unavailable") from e
        if response.status_code != 200:
            logger.error(
                f"{step} returned HTTP {response.status_code}: {response.text[:500]}"
            )
            message = f"{step} returned HTTP {response.status_code}"
            if response.status_code >= 500 or response.status_code == 429:
                raise UpstreamServiceError(message)
            raise AuthenticationError(message)
        try:
            body = response.json()
        except ValueError as e:
            logger.error(f"{step} returned a malformed body")
            raise AuthenticationError(f"{step} returned a malformed response") from e
        if not isinstance(body, dict):
            logger.error(f"{step} returned a non-object body")
            raise AuthenticationError(f"{step} returned a malformed response")
        return body


def _required_token(body: dict[str, object], key: str, step: str) -> str:
    """The non-empty string at ``body[key]``.

    Raises:
        AuthenticationError: The value is missing, empty or not a string.
    """
    token = body.get(key)
    if not isinstance(token, str) or not token:
        raise AuthenticationError(f"{step} returned an empty token")
    return token


def _expires_in(value: object) -> int:
    """Parse an OAuth ``expires_in`` JSON value (seconds).

    Raises:
        ValueError: Not a number or numeric string.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("expires_in is not a number")
    return int(value)


def _rfc3339(value: object) -> datetime:
    """Parse a Google ``Timestamp`` JSON value into an aware datetime.

    Raises:
        ValueError: Not an RFC 3339 string.
    """
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class AnthropicTokenExchange(_HttpTokenExchange):
    """Exchange adapter for Anthropic's RFC 7523 JWT-bearer token endpoint."""

    @capture_async(name="anthropic_exchange")
    async def exchange(self, proof: str, secret: AnthropicWifSecret) -> MintedToken:
        """POST the STS web identity token to ``https://<host>/v1/oauth/token``.

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response.
            AuthenticationError: Any other non-200 response, or a response
                without ``access_token`` and ``expires_in``.
        """
        step = f"Token exchange with {secret.host}"
        requested_at = datetime.now(timezone.utc)
        body = await self._post_json(
            step,
            f"https://{secret.host}/v1/oauth/token",
            json_body={
                "grant_type": JWT_BEARER_GRANT_TYPE,
                "assertion": proof,
                "federation_rule_id": secret.federation_rule_id,
                "organization_id": secret.organization_id,
                "service_account_id": secret.service_account_id,
                "workspace_id": secret.workspace_id,
            },
        )
        try:
            expires_in = _expires_in(body.get("expires_in"))
        except ValueError as e:
            logger.error(f"{step} returned a malformed body")
            raise AuthenticationError(f"{step} returned a malformed response") from e
        return MintedToken(
            token=_required_token(body, "access_token", step),
            expires_at=requested_at + timedelta(seconds=expires_in),
        )


class GcpTokenExchange(_HttpTokenExchange):
    """Exchange adapter for Google workload identity federation.

    Two calls: Google STS trades the signed ``GetCallerIdentity`` request for
    a federated token scoped to the IAM Credentials API, which then issues an
    access token for the secret's service account.
    """

    @capture_async(name="gcp_exchange")
    async def exchange(self, proof: str, secret: GcpWifSecret) -> MintedToken:
        """Obtain an access token for ``secret.service_account``.

        Args:
            proof: The signed ``GetCallerIdentity`` request, serialized as
                Google's ``aws4_request`` subject token
            secret: The ``gcp_wif`` secret

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response, from either call.
            AuthenticationError: Google STS or IAM Credentials refused, or a
                response was malformed.
        """
        exchange = f"Google STS exchange for {secret.service_account}"
        federated = await self._post_json(
            exchange,
            GOOGLE_STS_TOKEN_URL,
            data={
                "grant_type": GOOGLE_TOKEN_EXCHANGE_GRANT_TYPE,
                "audience": secret.audience,
                "scope": GOOGLE_IAM_SCOPE,
                "requested_token_type": GOOGLE_ACCESS_TOKEN_TYPE,
                "subject_token_type": AWS_SUBJECT_TOKEN_TYPE,
                "subject_token": proof,
            },
        )
        federated_token = _required_token(federated, "access_token", exchange)

        impersonation = f"Impersonation of {secret.service_account}"
        access = await self._post_json(
            impersonation,
            GOOGLE_IAM_CREDENTIALS_URL.format(service_account=secret.service_account),
            headers={"Authorization": f"Bearer {federated_token}"},
            json_body={
                "scope": secret.scopes,
                "lifetime": f"{secret.token_lifetime_seconds}s",
            },
        )
        try:
            expires_at = _rfc3339(access.get("expireTime"))
        except ValueError as e:
            logger.error(f"{impersonation} returned an unparseable expireTime")
            raise AuthenticationError(
                f"{impersonation} returned a malformed response"
            ) from e
        return MintedToken(
            token=_required_token(access, "accessToken", impersonation),
            expires_at=expires_at,
        )


class _TokenExchange[S: MintSecretBase](Protocol):
    """The shape every exchange adapter exposes, for its own secret type."""

    async def exchange(self, proof: str, secret: S) -> MintedToken: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True)
class _MintRoute[S: MintSecretBase]:
    """How one secret type is minted.

    Attributes:
        prove: Prove the federation identity for the secret, in the form its
            provider verifies
        adapter: Exchange that proof for the provider's token
    """

    prove: Callable[[FederationIdentity, S], Awaitable[str]]
    adapter: _TokenExchange[S]


class TokenMintService:
    """Mint an upstream token for a secret that describes how to obtain one.

    A new provider needs a ``MintSecretBase`` subclass, an adapter with the
    ``exchange(proof, secret)`` shape, and one entry in ``_routes``.
    """

    def __init__(
        self,
        sts: Optional[StsFederationService] = None,
        anthropic: Optional[AnthropicTokenExchange] = None,
        gcp: Optional[GcpTokenExchange] = None,
        federation_config: Optional[FederationConfig] = None,
        boto_session: Optional[AioSession] = None,
    ) -> None:
        self.federation_config = federation_config or config.federation
        self.sts = sts or StsFederationService(
            boto_session=boto_session, federation_config=self.federation_config
        )
        self.anthropic = anthropic or AnthropicTokenExchange()
        self.gcp = gcp or GcpTokenExchange()
        # Each route is typed for its own secret class, which the dict cannot
        # express; mint() looks a route up by the secret's exact type.
        self._routes: dict[type[MintSecretBase], _MintRoute[Any]] = {
            AnthropicWifSecret: _MintRoute(self._web_identity_proof, self.anthropic),
            GcpWifSecret: _MintRoute(self._signed_caller_identity_proof, self.gcp),
        }

    async def aclose(self) -> None:
        """Release every adapter's resources."""
        for route in self._routes.values():
            await route.adapter.aclose()

    async def _web_identity_proof(
        self, identity: FederationIdentity, secret: AnthropicWifSecret
    ) -> str:
        return (await self.sts.web_identity_token(identity, secret.audience)).token

    async def _signed_caller_identity_proof(
        self, identity: FederationIdentity, secret: GcpWifSecret
    ) -> str:
        return await self.sts.signed_caller_identity(identity, secret.audience)

    @capture_async()
    async def mint(
        self,
        credentials: AwsCredentials,
        principal: PrincipalInfo,
        secret: MintSecretBase,
    ) -> MintedToken:
        """Validate the federation role, prove the caller's identity, and exchange.

        Raises:
            AuthenticationError: Role not allowed, no route for the secret
                type, STS refused, or the exchange failed.
            CredentialsError: Caller credentials expired, not an assumed role,
                or an identity field unusable as a session tag.
            UpstreamServiceError: STS or the provider was unavailable, or
                minting exceeded ``MINT_DEADLINE_SECONDS``.
            ConfigurationError: The proof needs an AWS region and none is
                configured.
        """
        validate_federation_role_arn(
            secret.federation_role_arn,
            self.federation_config.allowed_account_ids,
            self.federation_config.role_path_prefix,
        )
        route = self._routes.get(type(secret))
        if route is None:
            raise AuthenticationError(
                f"No token exchange for secret type {type(secret).__name__}"
            )
        try:
            async with asyncio.timeout(MINT_DEADLINE_SECONDS):
                identity = await self.sts.assume_federation_role(
                    credentials, principal, secret.federation_role_arn
                )
                proof = await route.prove(identity, secret)
                return await route.adapter.exchange(proof, secret)
        except TimeoutError as e:
            logger.error(f"Token minting exceeded {MINT_DEADLINE_SECONDS} s")
            raise UpstreamServiceError("Token minting timed out") from e
