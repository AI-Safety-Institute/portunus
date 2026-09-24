"""
Short-lived upstream tokens minted from federation roles.

Minting has two independent parts:

1. Identity proof (:class:`StsFederationService`): with the caller's own
   credentials, assume the secret's federation role, then have that session
   request an STS web identity token. The result is a signed JWT whose subject
   is the federation role and whose tags carry the user, the caller's role
   name, its session name and the project, as they are, pseudonymised or not
   at all, per the secret's ``attribution``.
2. Exchange: trade the JWT for a provider bearer token. Each provider has an
   adapter with the same ``exchange(proof, secret)`` shape.
   :class:`AnthropicTokenExchange`, :class:`OpenAiTokenExchange` and
   :class:`OpenRouterTokenExchange` post the JWT to the provider's token
   endpoint; :class:`GcpTokenExchange` trades it at Google STS and
   impersonates a service account with the result.

:class:`TokenMintService` pairs each secret type with its proof and adapter.
"""

import asyncio
import hashlib
import hmac
import logging
import re
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Protocol, Sequence

import httpx
from aiobotocore.config import AioConfig
from aiobotocore.session import AioSession, get_session
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from portunus.config import FederationConfig, config
from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
    UpstreamServiceError,
)
from portunus.models import (
    AnthropicWifSecret,
    Attribution,
    AwsCredentials,
    GcpWifSecret,
    MintSecretBase,
    OpenAiWifSecret,
    OpenRouterWifSecret,
    PrincipalInfo,
)
from portunus.services.xray_service import capture_async

logger = logging.getLogger("api.access")

JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ANTHROPIC_TOKEN_URL = "https://api.anthropic.com/v1/oauth/token"
TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
# The algorithms STS GetWebIdentityToken signs with.
SigningAlgorithm = Literal["RS256", "ES384"]
# The session must outlive the identity token by more than the call latency:
# GetWebIdentityToken rejects a DurationSeconds longer than the session's
# remaining lifetime (SessionDurationEscalationException), so a 900 s session
# cannot issue a 900 s token. Keep this above every identity token lifetime.
FEDERATION_SESSION_SECONDS = 3600
IDENTITY_TOKEN_SECONDS = 900
# OpenAI tokens never outlive the identity token; Anthropic's are capped at
# twice its remaining life. Both settle at roughly 30-minute provider tokens.
OPENAI_IDENTITY_TOKEN_SECONDS = 1800
IDENTITY_TOKEN_SIGNING_ALGORITHM: SigningAlgorithm = "RS256"
# OpenAI: "Use ES384 unless your environment requires RS256 compatibility."
OPENAI_IDENTITY_TOKEN_SIGNING_ALGORITHM: SigningAlgorithm = "ES384"
OPENAI_TOKEN_URL = "https://auth.openai.com/oauth/token"
# OpenRouter verifies ES256 or RS256 subject tokens; of the algorithms STS
# signs with, only RS256 qualifies.
OPENROUTER_IDENTITY_TOKEN_SIGNING_ALGORITHM: SigningAlgorithm = "RS256"
# OpenRouter tokens live at most 15 minutes and never outlive the identity
# token, so a longer identity token buys nothing.
OPENROUTER_IDENTITY_TOKEN_SECONDS = 900
OPENROUTER_TOKEN_URL = "https://openrouter.ai/api/v1/oauth/token"
GOOGLE_STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"
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
PSEUDONYM_HEX_LENGTH = 16
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
# Two hops per mint (Google STS, then IAM Credentials) that, after AssumeRole,
# must fit inside MINT_DEADLINE_SECONDS.
_GCP_HOP_TIMEOUT = httpx.Timeout(3.0, connect=1.0)


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


def pseudonym(key: str, tag_key: str, value: str) -> str:
    """A keyed pseudonym for one tag value; an empty value stays empty.

    The first ``PSEUDONYM_HEX_LENGTH`` hex characters of HMAC-SHA256 over
    ``<tag_key>:<value>`` under ``key``. The tag key is part of the input so
    one value carried under two tags gets two unrelated pseudonyms.
    """
    if not value:
        return ""
    digest = hmac.new(key.encode(), f"{tag_key}:{value}".encode(), hashlib.sha256)
    return digest.hexdigest()[:PSEUDONYM_HEX_LENGTH]


def require_attribution_key(federation_config: FederationConfig) -> str:
    """The key ``pseudonymous`` attribution pseudonymises with.

    Raises:
        ConfigurationError: ``FEDERATION_ATTRIBUTION_KEY`` is not set. Real
            values are never sent in its place.
    """
    key = federation_config.attribution_key
    if not key:
        logger.error(
            "Secret requests pseudonymous attribution but "
            "FEDERATION_ATTRIBUTION_KEY is not set"
        )
        raise ConfigurationError(
            "Pseudonymous attribution requires FEDERATION_ATTRIBUTION_KEY"
        )
    return key


def identity_token_tags(
    identity: FederationIdentity,
    federation_config: FederationConfig,
    attribution: Attribution,
) -> Optional[list[dict[str, str]]]:
    """The ``Tags`` for GetWebIdentityToken, or None to send none.

    ``full`` carries the identity's user, principal, session and project under
    the configured tag keys; ``pseudonymous`` carries a :func:`pseudonym` of
    each, with an empty project staying empty; ``none`` returns None.

    Raises:
        ConfigurationError: ``pseudonymous`` without
            ``FEDERATION_ATTRIBUTION_KEY``.
    """
    if attribution == "none":
        return None
    tags = [
        (federation_config.user_tag_key, identity.user),
        (federation_config.principal_tag_key, identity.principal),
        (federation_config.session_tag_key, identity.session),
        (federation_config.project_tag_key, identity.project),
    ]
    if attribution == "pseudonymous":
        key = require_attribution_key(federation_config)
        tags = [(tag_key, pseudonym(key, tag_key, value)) for tag_key, value in tags]
    return [{"Key": tag_key, "Value": value} for tag_key, value in tags]


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

    def endpoint_url(self) -> str:
        """Resolve the STS endpoint for federation calls.

        Raises:
            ConfigurationError: No explicit endpoint and no region configured.
        """
        explicit = self.federation_config.sts_endpoint_url or config.aws.endpoint_url
        if explicit:
            return explicit
        region = self.boto_session.get_config_variable("region")
        if not region:
            raise ConfigurationError(
                "AWS region is required to build the regional STS endpoint"
            )
        return f"https://sts.{region}.amazonaws.com"

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
        self,
        identity: FederationIdentity,
        audience: str,
        signing_algorithm: SigningAlgorithm = IDENTITY_TOKEN_SIGNING_ALGORITHM,
        duration_seconds: int = IDENTITY_TOKEN_SECONDS,
        *,
        attribution: Attribution = "full",
    ) -> WebIdentityToken:
        """Issue a fresh STS-signed JWT for ``audience`` from the federation session.

        Providers treat the JWT ID as single-use, so callers must request a new
        token for every exchange rather than reuse one. ``signing_algorithm``
        is whichever the provider prefers. ``duration_seconds`` is the token's
        lifetime, which bounds the provider token's; STS accepts 60 to 3600 s
        and the value must fall inside the federation session's remaining life.
        ``attribution`` decides what the token's request tags carry; see
        :func:`identity_token_tags`.

        Raises:
            ValueError: ``duration_seconds`` is outside STS's 60..3600 s range.
            ConfigurationError: ``pseudonymous`` attribution without
                ``FEDERATION_ATTRIBUTION_KEY``.
            AuthenticationError: STS refused to issue the token.
            UpstreamServiceError: STS could not be reached.
        """
        if not 60 <= duration_seconds <= 3600:
            raise ValueError(
                f"duration_seconds must be between 60 and 3600, got {duration_seconds}"
            )
        request: dict[str, Any] = {
            "Audience": [audience],
            "SigningAlgorithm": signing_algorithm,
            "DurationSeconds": duration_seconds,
        }
        tags = identity_token_tags(identity, self.federation_config, attribution)
        if tags is not None:
            request["Tags"] = tags
        try:
            async with self.boto_session.create_client(
                "sts",
                aws_access_key_id=identity.credentials.access_key_id,
                aws_secret_access_key=identity.credentials.secret_access_key,
                aws_session_token=identity.credentials.session_token,
                endpoint_url=self.endpoint_url(),
                config=_STS_CLIENT_CONFIG,
            ) as sts:
                response = await sts.get_web_identity_token(**request)
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

        ``step`` names the call in messages and logs. Messages reach the
        client, so ``step`` must not carry secret fields; logs carry the
        response status and (truncated) body but never the request.

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
            # Not chained: the exception carries the request, whose body holds
            # the proof or federated token.
            logger.error(f"{step} failed: {type(e).__name__}: {e}")
            raise UpstreamServiceError(f"{step} is unavailable") from None
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


class OAuthTokenResponse(BaseModel):
    """The fields of an OAuth 2.0 token response that minting uses.

    Providers add others (``token_type``, ``scope``, ``expires_at``), which
    are ignored.
    """

    model_config = ConfigDict(extra="ignore")

    access_token: str = Field(min_length=1)
    expires_in: int = Field(gt=0)

    def minted_token(self, requested_at: datetime) -> MintedToken:
        """The token, expiring ``expires_in`` seconds after ``requested_at``.

        ``requested_at`` is when the request was sent, so the expiry is never
        later than the provider's.
        """
        return MintedToken(
            token=self.access_token,
            expires_at=requested_at + timedelta(seconds=self.expires_in),
        )


def _parse_response[M: BaseModel](model: type[M], body: object, step: str) -> M:
    """Validate a 200 response body as ``model``.

    The body may hold a token, so it is not logged.

    Raises:
        AuthenticationError: The body does not fit ``model``.
    """
    try:
        return model.model_validate(body)
    except ValidationError as e:
        logger.error(f"{step} returned a malformed body")
        raise AuthenticationError(f"{step} returned a malformed response") from e


class GoogleAccessTokenResponse(BaseModel):
    """The fields of an IAM Credentials ``generateAccessToken`` response.

    ``expireTime`` is a Google ``Timestamp`` (RFC 3339 in UTC). Its
    nanoseconds are truncated to microseconds, never rounded up, so the
    expiry is never later than Google's.
    """

    model_config = ConfigDict(extra="ignore")

    accessToken: str = Field(min_length=1)
    expireTime: AwareDatetime

    def minted_token(self) -> MintedToken:
        """The token and Google's expiry."""
        return MintedToken(token=self.accessToken, expires_at=self.expireTime)


class AnthropicTokenExchange(_HttpTokenExchange):
    """Exchange adapter for Anthropic's RFC 7523 JWT-bearer token endpoint."""

    @capture_async(name="anthropic_exchange")
    async def exchange(self, proof: str, secret: AnthropicWifSecret) -> MintedToken:
        """POST the STS web identity token to ``ANTHROPIC_TOKEN_URL``.

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response.
            AuthenticationError: Any other non-200 response, or a response
                without ``access_token`` and ``expires_in``.
        """
        step = "Anthropic token exchange"
        requested_at = datetime.now(timezone.utc)
        body = await self._post_json(
            step,
            ANTHROPIC_TOKEN_URL,
            json_body={
                "grant_type": JWT_BEARER_GRANT_TYPE,
                "assertion": proof,
                "federation_rule_id": secret.federation_rule_id,
                "organization_id": secret.organization_id,
                "service_account_id": secret.service_account_id,
                "workspace_id": secret.workspace_id,
            },
        )
        token = _parse_response(OAuthTokenResponse, body, step)
        return token.minted_token(requested_at)


class OpenAiTokenExchange(_HttpTokenExchange):
    """Exchange adapter for OpenAI's RFC 8693 token exchange endpoint."""

    @capture_async(name="openai_exchange")
    async def exchange(self, proof: str, secret: OpenAiWifSecret) -> MintedToken:
        """POST the STS web identity token to ``OPENAI_TOKEN_URL``.

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response.
            AuthenticationError: Any other non-200 response, or a response
                without ``access_token`` and ``expires_in``.
        """
        step = "Token exchange with OpenAI"
        requested_at = datetime.now(timezone.utc)
        body = await self._post_json(
            step,
            OPENAI_TOKEN_URL,
            json_body={
                "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
                "subject_token_type": JWT_TOKEN_TYPE,
                "subject_token": proof,
                "identity_provider_id": secret.identity_provider_id,
                "service_account_id": secret.service_account_id,
            },
        )
        token = _parse_response(OAuthTokenResponse, body, step)
        return token.minted_token(requested_at)


class OpenRouterTokenExchange(_HttpTokenExchange):
    """Exchange adapter for OpenRouter's RFC 8693 token exchange endpoint."""

    @capture_async(name="openrouter_exchange")
    async def exchange(self, proof: str, secret: OpenRouterWifSecret) -> MintedToken:
        """POST the STS web identity token to ``OPENROUTER_TOKEN_URL`` as a form.

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response.
            AuthenticationError: Any other non-200 response, or a response
                without ``access_token`` and ``expires_in``.
        """
        step = "Token exchange with OpenRouter"
        requested_at = datetime.now(timezone.utc)
        body = await self._post_json(
            step,
            OPENROUTER_TOKEN_URL,
            data={
                "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
                "subject_token_type": JWT_TOKEN_TYPE,
                "subject_token": proof,
                "federation_policy_id": secret.federation_policy_id,
            },
        )
        token = _parse_response(OAuthTokenResponse, body, step)
        return token.minted_token(requested_at)


class GcpTokenExchange(_HttpTokenExchange):
    """Exchange adapter for Google workload identity federation.

    Two calls: Google STS trades the STS web identity token (RFC 8693 token
    exchange, the JWT as an OIDC subject token) for a federated token scoped
    to the IAM Credentials API, which then issues an access token for the
    secret's service account.
    """

    timeout = _GCP_HOP_TIMEOUT

    @capture_async(name="gcp_exchange")
    async def exchange(self, proof: str, secret: GcpWifSecret) -> MintedToken:
        """Obtain an access token for ``secret.service_account``.

        Args:
            proof: The STS web identity token issued for ``secret.audience``
            secret: The ``gcp_wif`` secret

        Raises:
            UpstreamServiceError: Transport failure, or an HTTP 5xx or 429
                response, from either call.
            AuthenticationError: Google STS or IAM Credentials refused, or a
                response was malformed.
        """
        exchange = "Google STS exchange"
        impersonation = "Google service-account impersonation"
        try:
            federated = await self._post_json(
                exchange,
                GOOGLE_STS_TOKEN_URL,
                data={
                    "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
                    "audience": secret.audience,
                    "scope": GOOGLE_IAM_SCOPE,
                    "requested_token_type": GOOGLE_ACCESS_TOKEN_TYPE,
                    "subject_token_type": JWT_TOKEN_TYPE,
                    "subject_token": proof,
                },
            )
            federated_token = _parse_response(OAuthTokenResponse, federated, exchange)
            access = await self._post_json(
                impersonation,
                GOOGLE_IAM_CREDENTIALS_URL.format(
                    service_account=urllib.parse.quote(secret.service_account, safe="@")
                ),
                headers={"Authorization": f"Bearer {federated_token.access_token}"},
                json_body={
                    "scope": secret.scopes,
                    "lifetime": f"{secret.token_lifetime_seconds}s",
                },
            )
            token = _parse_response(GoogleAccessTokenResponse, access, impersonation)
        except (AuthenticationError, UpstreamServiceError) as e:
            # The step names reach the client in the message, so the service
            # account is named only here.
            logger.error(
                f"GCP exchange for {secret.service_account} failed: {e.message}"
            )
            raise
        return token.minted_token()


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
        openai: Optional[OpenAiTokenExchange] = None,
        openrouter: Optional[OpenRouterTokenExchange] = None,
        federation_config: Optional[FederationConfig] = None,
        boto_session: Optional[AioSession] = None,
    ) -> None:
        self.federation_config = federation_config or config.federation
        self.sts = sts or StsFederationService(
            boto_session=boto_session, federation_config=self.federation_config
        )
        self.anthropic = anthropic or AnthropicTokenExchange()
        self.gcp = gcp or GcpTokenExchange()
        self.openai = openai or OpenAiTokenExchange()
        self.openrouter = openrouter or OpenRouterTokenExchange()
        # Each route is typed for its own secret class, which the dict cannot
        # express; mint() looks a route up by the secret's exact type.
        self._routes: dict[type[MintSecretBase], _MintRoute[Any]] = {
            AnthropicWifSecret: _MintRoute(self._web_identity_proof, self.anthropic),
            OpenAiWifSecret: _MintRoute(self._openai_identity_proof, self.openai),
            OpenRouterWifSecret: _MintRoute(
                self._openrouter_identity_proof, self.openrouter
            ),
            GcpWifSecret: _MintRoute(self._web_identity_proof, self.gcp),
        }

    async def aclose(self) -> None:
        """Release every adapter's resources."""
        for route in self._routes.values():
            await route.adapter.aclose()

    async def _web_identity_proof(
        self, identity: FederationIdentity, secret: AnthropicWifSecret | GcpWifSecret
    ) -> str:
        token = await self.sts.web_identity_token(
            identity, secret.audience, attribution=secret.attribution
        )
        return token.token

    async def _openai_identity_proof(
        self, identity: FederationIdentity, secret: OpenAiWifSecret
    ) -> str:
        token = await self.sts.web_identity_token(
            identity,
            secret.audience,
            OPENAI_IDENTITY_TOKEN_SIGNING_ALGORITHM,
            OPENAI_IDENTITY_TOKEN_SECONDS,
            attribution=secret.attribution,
        )
        return token.token

    async def _openrouter_identity_proof(
        self, identity: FederationIdentity, secret: OpenRouterWifSecret
    ) -> str:
        token = await self.sts.web_identity_token(
            identity,
            secret.audience,
            OPENROUTER_IDENTITY_TOKEN_SIGNING_ALGORITHM,
            OPENROUTER_IDENTITY_TOKEN_SECONDS,
            attribution=secret.attribution,
        )
        return token.token

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
            ConfigurationError: The secret's ``attribution`` is
                ``pseudonymous`` and ``FEDERATION_ATTRIBUTION_KEY`` is not set.
            CredentialsError: Caller credentials expired, not an assumed role,
                or an identity field unusable as a session tag.
            UpstreamServiceError: STS or the provider was unavailable, or
                minting exceeded ``MINT_DEADLINE_SECONDS``.
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
        # identity_token_tags() would also raise, but only after AssumeRole.
        if secret.attribution == "pseudonymous":
            require_attribution_key(self.federation_config)
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
