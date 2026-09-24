"""Tests for minting short-lived upstream tokens via federation roles."""

import asyncio
import json
import logging
import re
import threading
import urllib.parse
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Literal
from unittest.mock import AsyncMock, MagicMock

import botocore.auth
import httpx
import pytest
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from google.auth import _helpers as google_helpers

from portunus.config import FederationConfig
from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
    UpstreamServiceError,
)
from portunus.models import (
    GCP_CLOUD_PLATFORM_SCOPE,
    OPENAI_API_AUDIENCE,
    OPENROUTER_API_AUDIENCE,
    AnthropicWifSecret,
    AwsCredentials,
    GcpWifSecret,
    MintSecretBase,
    OpenAiWifSecret,
    OpenRouterWifSecret,
    PrincipalInfo,
)
from portunus.services import federation_service
from portunus.services.federation_service import (
    AWS_GET_CALLER_IDENTITY_URL,
    AWS_SUBJECT_TOKEN_TYPE,
    FEDERATION_SESSION_SECONDS,
    GOOGLE_ACCESS_TOKEN_TYPE,
    GOOGLE_IAM_SCOPE,
    GOOGLE_STS_TOKEN_URL,
    IDENTITY_TOKEN_SECONDS,
    JWT_BEARER_GRANT_TYPE,
    JWT_TOKEN_TYPE,
    OPENAI_IDENTITY_TOKEN_SECONDS,
    OPENAI_IDENTITY_TOKEN_SIGNING_ALGORITHM,
    OPENAI_TOKEN_URL,
    OPENROUTER_IDENTITY_TOKEN_SECONDS,
    OPENROUTER_IDENTITY_TOKEN_SIGNING_ALGORITHM,
    OPENROUTER_TOKEN_URL,
    TOKEN_EXCHANGE_GRANT_TYPE,
    AnthropicTokenExchange,
    FederationIdentity,
    GcpTokenExchange,
    MintedToken,
    OAuthTokenResponse,
    OpenAiTokenExchange,
    OpenRouterTokenExchange,
    StsFederationService,
    TokenMintService,
    WebIdentityToken,
    caller_project,
    caller_role_name,
    caller_session,
    caller_user,
    validate_federation_role_arn,
)

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/"
    "example-grant@projects.example"
)
CALLER_ROLE = "UserProfile_TestUser_example"
CALLER = PrincipalInfo(
    arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/{CALLER_ROLE}/session",
    account_id=ACCOUNT,
    principal=f"assumed-role/{CALLER_ROLE}",
    session_name="session",
    project="example",
)
SOURCE_IDENTITY = "someone@example.com"
CALLER_CREDENTIALS = AwsCredentials(
    access_key_id="AKIACALLER",
    secret_access_key="caller-secret",
    session_token="caller-token",
)
STS_ENDPOINT = "https://sts.eu-west-2.amazonaws.com"
FEDERATION_CONFIG = FederationConfig(
    allowed_account_ids=[ACCOUNT], sts_endpoint_url=STS_ENDPOINT
)
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
REGION = "eu-west-2"
GCP_AUDIENCE = (
    "//iam.googleapis.com/projects/123456789/locations/global/"
    "workloadIdentityPools/example-pool/providers/example-provider"
)
GCP_SERVICE_ACCOUNT = "example-sa@example-project.iam.gserviceaccount.com"
GCP_IAM_URL = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
    f"{GCP_SERVICE_ACCOUNT}:generateAccessToken"
)
# Stands in for the GCP identity proof (an STS web identity token or a signed
# GetCallerIdentity request) in adapter tests.
PROOF = "identity-proof"


def _secret(**overrides: object) -> AnthropicWifSecret:
    data: dict[str, object] = {
        "type": "anthropic_wif",
        "host": "api.example.com",
        "federation_role_arn": ROLE_ARN,
        "federation_rule_id": "fr_example",
        "organization_id": "org_example",
        "service_account_id": "sa_example",
        "workspace_id": "ws_example",
    }
    data.update(overrides)
    return AnthropicWifSecret.model_validate(data)


def _gcp_secret(**overrides: object) -> GcpWifSecret:
    data: dict[str, object] = {
        "type": "gcp_wif",
        "host": "aiplatform.googleapis.com",
        "federation_role_arn": ROLE_ARN,
        "audience": GCP_AUDIENCE,
        "service_account": GCP_SERVICE_ACCOUNT,
    }
    data.update(overrides)
    return GcpWifSecret.model_validate(data)


def _openai_secret(**overrides: object) -> OpenAiWifSecret:
    data: dict[str, object] = {
        "type": "openai_wif",
        "host": "api.openai.com",
        "federation_role_arn": ROLE_ARN,
        "identity_provider_id": "idp_example",
        "service_account_id": "svc_acct_example",
    }
    data.update(overrides)
    return OpenAiWifSecret.model_validate(data)


def _openrouter_secret(**overrides: object) -> OpenRouterWifSecret:
    data: dict[str, object] = {
        "type": "openrouter_wif",
        "host": "openrouter.ai",
        "federation_role_arn": ROLE_ARN,
        "federation_policy_id": "fedpol_example",
    }
    data.update(overrides)
    return OpenRouterWifSecret.model_validate(data)


def _identity() -> FederationIdentity:
    return FederationIdentity(
        credentials=AwsCredentials(
            access_key_id="ASIAFED",
            secret_access_key="fed-secret",
            session_token="fed-token",
            expiration=NOW + timedelta(minutes=15),
        ),
        user=CALLER_ROLE,
        principal=CALLER_ROLE,
        session="session",
        project="example",
    )


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError(
        error_response={"Error": {"Code": code, "Message": code}},
        operation_name=operation,
    )


class TestValidateFederationRoleArn:
    def test_accepts_a_role_under_the_prefix_in_an_allowed_account(self):
        validate_federation_role_arn(ROLE_ARN, [ACCOUNT], "/portunus-fed/")

    @pytest.mark.parametrize(
        "arn",
        [
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/Type.1/a_b+c=d,e@f~g/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/t/s/{'n' * 64}",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/t/s/n",
        ],
    )
    def test_accepts_iam_path_and_role_name_charsets(self, arn: str):
        validate_federation_role_arn(arn, [ACCOUNT], "/portunus-fed/")

    @pytest.mark.parametrize(
        "arn",
        [
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/example-grant/"
            "example-grant@projects.example",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/extra/name",
        ],
    )
    def test_accepts_any_path_depth_under_the_prefix(self, arn: str):
        validate_federation_role_arn(arn, [ACCOUNT], "/portunus-fed/")

    @pytest.mark.parametrize(
        "arn",
        [
            f"arn:aws:iam::{ACCOUNT}:role/example-grant@projects.example",
            f"arn:aws:iam::{ACCOUNT}:role/other/projects/example/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed-x/projects/example/name",
            f"arn:aws:iam::{ACCOUNT}:role/x/portunus-fed/projects/example/name",
        ],
    )
    def test_rejects_roles_outside_the_path_prefix(self, arn: str):
        with pytest.raises(AuthenticationError, match="role path"):
            validate_federation_role_arn(arn, [ACCOUNT], "/portunus-fed/")

    def test_rejects_roles_in_other_accounts(self):
        arn = f"arn:aws:iam::{OTHER_ACCOUNT}:role/portunus-fed/projects/example/name"
        with pytest.raises(AuthenticationError, match="allowed account"):
            validate_federation_role_arn(arn, [ACCOUNT], "/portunus-fed/")

    @pytest.mark.parametrize(
        "arn",
        [
            f"arn:aws:iam::{ACCOUNT}:user/portunus-fed/projects/example/name",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/portunus-fed/name",
            f"arn:aws:iam::{ACCOUNT[:-1]}:role/portunus-fed/projects/example/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed//example/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects//name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/name\n",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/na me",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/exa mple/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/ex\u00e4mple/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/name:x",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/{'n' * 65}",
            "not-an-arn",
            "",
        ],
    )
    def test_rejects_malformed_role_arns(self, arn: str):
        with pytest.raises(AuthenticationError, match="not an IAM role ARN"):
            validate_federation_role_arn(arn, [ACCOUNT], "/portunus-fed/")

    def test_empty_allowlist_disables_minting(self):
        with pytest.raises(AuthenticationError, match="disabled"):
            validate_federation_role_arn(ROLE_ARN, [], "/portunus-fed/")

    def test_path_prefix_is_configurable(self):
        arn = f"arn:aws:iam::{ACCOUNT}:role/custom-fed/projects/example/name"
        validate_federation_role_arn(arn, [ACCOUNT], "/custom-fed/")
        with pytest.raises(AuthenticationError, match="role path"):
            validate_federation_role_arn(ROLE_ARN, [ACCOUNT], "/custom-fed/")


class TestCallerIdentityFields:
    def test_principal_is_the_callers_role_name(self):
        assert caller_role_name(CALLER) == CALLER_ROLE

    @pytest.mark.parametrize(
        "principal",
        [None, "user/someone", "assumed-role/a", "assumed-role/" + "x" * 65],
    )
    def test_unusable_principals_are_rejected(self, principal: str | None):
        with pytest.raises(CredentialsError):
            caller_role_name(PrincipalInfo(principal=principal))

    def test_project_tag_is_empty_when_unknown(self):
        assert caller_project(CALLER) == "example"
        assert caller_project(PrincipalInfo(project="unknown")) == ""
        assert caller_project(PrincipalInfo(project=None)) == ""

    def test_principal_with_a_comma_cannot_be_a_session_tag(self):
        with pytest.raises(CredentialsError, match="session tag"):
            caller_role_name(PrincipalInfo(principal="assumed-role/role,name"))

    def test_project_with_a_comma_cannot_be_a_session_tag(self):
        with pytest.raises(CredentialsError, match="session tag"):
            caller_project(PrincipalInfo(project="team,project"))

    def test_session_is_the_callers_session_name(self):
        assert caller_session(CALLER) == "session"

    @pytest.mark.parametrize("session_name", [None, ""])
    def test_caller_without_a_session_name_is_rejected(self, session_name: str | None):
        principal = PrincipalInfo(
            principal=f"assumed-role/{CALLER_ROLE}", session_name=session_name
        )
        with pytest.raises(CredentialsError, match="assumed-role"):
            caller_session(principal)

    def test_session_name_with_a_comma_cannot_be_a_session_tag(self):
        with pytest.raises(CredentialsError, match="session tag"):
            caller_session(PrincipalInfo(session_name="i-0123,abc"))

    def test_user_is_the_source_identity_when_set(self):
        assert caller_user(CALLER_ROLE, SOURCE_IDENTITY) == SOURCE_IDENTITY

    @pytest.mark.parametrize("source_identity", [None, ""])
    def test_user_falls_back_to_the_role_name(self, source_identity: str | None):
        assert caller_user(CALLER_ROLE, source_identity) == CALLER_ROLE

    def test_source_identity_with_a_comma_cannot_be_a_session_tag(self):
        with pytest.raises(CredentialsError, match="session tag"):
            caller_user(CALLER_ROLE, "some,one")


def _sts_session(
    assume_role: object = None, get_web_identity_token: object = None
) -> tuple[MagicMock, list[AsyncMock]]:
    """A boto session whose STS clients are mocks; returns (session, clients)."""
    clients: list[AsyncMock] = []

    def create_client(service_name: str, **kwargs: object) -> AsyncMock:
        assert service_name == "sts"
        client = AsyncMock()
        client.create_kwargs = kwargs
        client.assume_role = AsyncMock(
            side_effect=assume_role if isinstance(assume_role, Exception) else None,
            return_value=assume_role,
        )
        client.get_web_identity_token = AsyncMock(
            side_effect=get_web_identity_token
            if isinstance(get_web_identity_token, Exception)
            else None,
            return_value=get_web_identity_token,
        )
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        clients.append(client)
        return client

    session = MagicMock()
    session.create_client = MagicMock(side_effect=create_client)
    return session, clients


ASSUME_ROLE_RESPONSE = {
    "Credentials": {
        "AccessKeyId": "ASIAFED",
        "SecretAccessKey": "fed-secret",
        "SessionToken": "fed-token",
        "Expiration": NOW + timedelta(minutes=15),
    }
}
WEB_IDENTITY_RESPONSE = {
    "WebIdentityToken": "header.payload.signature",
    "Expiration": NOW + timedelta(minutes=15),
}


class TestStsFederationService:
    @pytest.mark.asyncio
    async def test_assume_role_uses_caller_credentials_and_role_name(self):
        session, clients = _sts_session(assume_role=ASSUME_ROLE_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        identity = await service.assume_federation_role(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )

        (client,) = clients
        assert client.create_kwargs["aws_access_key_id"] == "AKIACALLER"
        assert client.create_kwargs["aws_secret_access_key"] == "caller-secret"
        assert client.create_kwargs["aws_session_token"] == "caller-token"
        assert client.create_kwargs["endpoint_url"] == STS_ENDPOINT
        assert client.create_kwargs["config"].retries == {
            "max_attempts": 1,
            "mode": "standard",
        }
        client.assume_role.assert_awaited_once_with(
            RoleArn=ROLE_ARN,
            RoleSessionName=CALLER_ROLE,
            DurationSeconds=FEDERATION_SESSION_SECONDS,
        )
        assert identity == _identity()

    @pytest.mark.asyncio
    async def test_source_identity_becomes_the_user_but_not_the_principal(self):
        session, _ = _sts_session(
            assume_role={**ASSUME_ROLE_RESPONSE, "SourceIdentity": SOURCE_IDENTITY}
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        identity = await service.assume_federation_role(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )

        assert identity.user == SOURCE_IDENTITY
        assert identity.principal == CALLER_ROLE
        assert identity == replace(_identity(), user=SOURCE_IDENTITY)

    @pytest.mark.asyncio
    async def test_source_identity_unusable_as_a_tag_is_rejected(self):
        session, _ = _sts_session(
            assume_role={**ASSUME_ROLE_RESPONSE, "SourceIdentity": "some,one"}
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(CredentialsError, match="session tag"):
            await service.assume_federation_role(CALLER_CREDENTIALS, CALLER, ROLE_ARN)

    @pytest.mark.asyncio
    async def test_non_assumed_role_caller_is_rejected_before_sts(self):
        session, clients = _sts_session(assume_role=ASSUME_ROLE_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(CredentialsError):
            await service.assume_federation_role(
                CALLER_CREDENTIALS, PrincipalInfo(principal=None), ROLE_ARN
            )

        assert clients == []

    @pytest.mark.asyncio
    async def test_caller_without_a_session_segment_is_rejected_before_sts(self):
        session, clients = _sts_session(assume_role=ASSUME_ROLE_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)
        principal = PrincipalInfo(principal=f"assumed-role/{CALLER_ROLE}")

        with pytest.raises(CredentialsError, match="assumed-role"):
            await service.assume_federation_role(
                CALLER_CREDENTIALS, principal, ROLE_ARN
            )

        assert clients == []

    @pytest.mark.parametrize(
        "principal",
        [
            PrincipalInfo(principal="assumed-role/role,name", session_name="session"),
            PrincipalInfo(principal=f"assumed-role/{CALLER_ROLE}", session_name="a,b"),
        ],
    )
    @pytest.mark.asyncio
    async def test_identity_unusable_as_a_tag_is_rejected_before_sts(
        self, principal: PrincipalInfo
    ):
        session, clients = _sts_session(assume_role=ASSUME_ROLE_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(CredentialsError, match="session tag"):
            await service.assume_federation_role(
                CALLER_CREDENTIALS, principal, ROLE_ARN
            )

        assert clients == []

    @pytest.mark.asyncio
    async def test_unreachable_sts_raises_upstream_service_error(self):
        session, _ = _sts_session(
            assume_role=EndpointConnectionError(endpoint_url=STS_ENDPOINT)
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(UpstreamServiceError, match="STS is unavailable") as e:
            await service.assume_federation_role(CALLER_CREDENTIALS, CALLER, ROLE_ARN)

        assert STS_ENDPOINT not in e.value.message

    @pytest.mark.asyncio
    async def test_expired_caller_credentials_raise_credentials_error(self):
        session, _ = _sts_session(
            assume_role=_client_error("ExpiredToken", "AssumeRole")
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(CredentialsError, match="expired"):
            await service.assume_federation_role(CALLER_CREDENTIALS, CALLER, ROLE_ARN)

    @pytest.mark.asyncio
    async def test_access_denied_raises_authentication_error(self):
        session, _ = _sts_session(
            assume_role=_client_error("AccessDenied", "AssumeRole")
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(AuthenticationError, match="AccessDenied"):
            await service.assume_federation_role(CALLER_CREDENTIALS, CALLER, ROLE_ARN)

    @pytest.mark.asyncio
    async def test_web_identity_token_uses_federation_session_and_tags(self):
        session, clients = _sts_session(get_web_identity_token=WEB_IDENTITY_RESPONSE)
        federation_config = FederationConfig(
            allowed_account_ids=[ACCOUNT],
            sts_endpoint_url=STS_ENDPOINT,
            user_tag_key="example:user",
            principal_tag_key="example:principal",
            session_tag_key="example:session",
            project_tag_key="example:project",
        )
        service = StsFederationService(session, federation_config)
        identity = replace(_identity(), user=SOURCE_IDENTITY)

        proof = await service.web_identity_token(identity, "https://api.example.com")

        (client,) = clients
        assert client.create_kwargs["aws_access_key_id"] == "ASIAFED"
        assert client.create_kwargs["aws_session_token"] == "fed-token"
        assert client.create_kwargs["endpoint_url"] == STS_ENDPOINT
        client.get_web_identity_token.assert_awaited_once_with(
            Audience=["https://api.example.com"],
            SigningAlgorithm="RS256",
            DurationSeconds=IDENTITY_TOKEN_SECONDS,
            Tags=[
                {"Key": "example:user", "Value": SOURCE_IDENTITY},
                {"Key": "example:principal", "Value": CALLER_ROLE},
                {"Key": "example:session", "Value": "session"},
                {"Key": "example:project", "Value": "example"},
            ],
        )
        assert proof == WebIdentityToken(
            token="header.payload.signature", expires_at=NOW + timedelta(minutes=15)
        )

    @pytest.mark.asyncio
    async def test_web_identity_token_signs_with_the_requested_algorithm(self):
        session, clients = _sts_session(get_web_identity_token=WEB_IDENTITY_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        await service.web_identity_token(_identity(), OPENAI_API_AUDIENCE, "ES384")

        (client,) = clients
        kwargs = client.get_web_identity_token.await_args.kwargs
        assert kwargs["Audience"] == [OPENAI_API_AUDIENCE]
        assert kwargs["SigningAlgorithm"] == "ES384"
        assert kwargs["DurationSeconds"] == IDENTITY_TOKEN_SECONDS

    @pytest.mark.asyncio
    async def test_web_identity_token_requests_the_given_duration(self):
        session, clients = _sts_session(get_web_identity_token=WEB_IDENTITY_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        await service.web_identity_token(
            _identity(), OPENAI_API_AUDIENCE, "ES384", duration_seconds=1800
        )

        (client,) = clients
        kwargs = client.get_web_identity_token.await_args.kwargs
        assert kwargs["DurationSeconds"] == 1800

    @pytest.mark.asyncio
    @pytest.mark.parametrize("duration_seconds", [59, 3601])
    async def test_web_identity_token_rejects_durations_outside_sts_bounds(
        self, duration_seconds: int
    ):
        session, clients = _sts_session(get_web_identity_token=WEB_IDENTITY_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(ValueError, match="between 60 and 3600"):
            await service.web_identity_token(
                _identity(), OPENAI_API_AUDIENCE, duration_seconds=duration_seconds
            )

        assert clients == []

    @pytest.mark.asyncio
    async def test_web_identity_token_failure_raises_authentication_error(self):
        session, _ = _sts_session(
            get_web_identity_token=_client_error("AccessDenied", "GetWebIdentityToken")
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(AuthenticationError, match="identity token"):
            await service.web_identity_token(_identity(), "https://api.example.com")

    @pytest.mark.asyncio
    async def test_web_identity_token_timeout_raises_upstream_service_error(self):
        session, _ = _sts_session(
            get_web_identity_token=ReadTimeoutError(endpoint_url=STS_ENDPOINT)
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(UpstreamServiceError, match="STS is unavailable") as e:
            await service.web_identity_token(_identity(), "https://api.example.com")

        assert STS_ENDPOINT not in e.value.message

    def test_endpoint_defaults_to_regional_sts(self):
        session = MagicMock()
        session.get_config_variable = MagicMock(return_value="us-west-2")
        service = StsFederationService(
            session, FederationConfig(allowed_account_ids=[ACCOUNT])
        )

        assert service.endpoint_url() == "https://sts.us-west-2.amazonaws.com"

    def test_endpoint_requires_a_region_when_not_explicit(self):
        session = MagicMock()
        session.get_config_variable = MagicMock(return_value=None)
        service = StsFederationService(
            session, FederationConfig(allowed_account_ids=[ACCOUNT])
        )

        with pytest.raises(ConfigurationError):
            service.endpoint_url()

    def test_region_comes_from_the_sdk_configuration(self):
        session = MagicMock()
        session.get_config_variable = MagicMock(return_value="us-west-2")
        service = StsFederationService(session, FEDERATION_CONFIG)

        assert service.region() == "us-west-2"
        session.get_config_variable.assert_called_once_with("region")

    def test_region_is_required_even_with_an_explicit_endpoint(self):
        session = MagicMock()
        session.get_config_variable = MagicMock(return_value=None)
        service = StsFederationService(session, FEDERATION_CONFIG)

        assert service.endpoint_url() == STS_ENDPOINT
        with pytest.raises(ConfigurationError):
            service.region()


def _decode_subject_token(token: str) -> tuple[dict, dict[str, str]]:
    """Decode an aws4_request subject token into (request, lower-cased headers)."""
    request = json.loads(urllib.parse.unquote(token))
    headers = {h["key"].lower(): h["value"] for h in request["headers"]}
    return request, headers


_SIGV4_AUTHORIZATION = re.compile(
    r"^AWS4-HMAC-SHA256 Credential=ASIAFED/\d{8}/eu-west-2/sts/aws4_request, "
    r"SignedHeaders=(?P<signed>[a-z0-9;-]+), Signature=[0-9a-f]{64}$"
)


def _regional_sts(region: str | None = REGION) -> StsFederationService:
    """An STS service whose SDK session is configured for ``region``."""
    session = MagicMock()
    session.get_config_variable = MagicMock(return_value=region)
    return StsFederationService(session, FEDERATION_CONFIG)


class TestSignedCallerIdentity:
    @pytest.mark.asyncio
    async def test_is_a_signed_regional_get_caller_identity_request(self):
        token = await _regional_sts().signed_caller_identity(_identity(), GCP_AUDIENCE)

        request, headers = _decode_subject_token(token)
        assert request["method"] == "POST"
        assert request["url"] == (
            f"https://sts.{REGION}.amazonaws.com"
            "?Action=GetCallerIdentity&Version=2011-06-15"
        )
        assert headers["host"] == f"sts.{REGION}.amazonaws.com"
        assert headers["x-amz-security-token"] == "fed-token"
        assert headers["x-goog-cloud-target-resource"] == GCP_AUDIENCE
        assert re.fullmatch(r"\d{8}T\d{6}Z", headers["x-amz-date"])
        match = _SIGV4_AUTHORIZATION.fullmatch(headers["authorization"])
        assert match is not None
        signed = set(match["signed"].split(";"))
        assert {"host", "x-amz-date", "x-goog-cloud-target-resource"} <= signed
        assert "x-amz-security-token" in signed

    @pytest.mark.asyncio
    async def test_signature_matches_botocore_sigv4(self, monkeypatch):
        monkeypatch.setattr(google_helpers, "utcnow", lambda: NOW)
        monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda: NOW)
        reference = AWSRequest(
            method="POST",
            url=AWS_GET_CALLER_IDENTITY_URL.format(region=REGION),
            headers={"x-goog-cloud-target-resource": GCP_AUDIENCE},
        )
        botocore.auth.SigV4Auth(
            Credentials("ASIAFED", "fed-secret", "fed-token"), "sts", REGION
        ).add_auth(reference)

        token = await _regional_sts().signed_caller_identity(_identity(), GCP_AUDIENCE)

        _, headers = _decode_subject_token(token)
        assert headers["x-amz-date"] == "20260101T120000Z"
        assert headers["authorization"] == reference.headers["Authorization"]
        assert headers["authorization"].endswith(
            "Signature=947d6faf284fc5ed8c9c2e2fef86189fb35bdbef9ade0dd5f5a02eff41db7d2b"
        )

    @pytest.mark.asyncio
    async def test_never_contains_the_secret_key(self):
        token = await _regional_sts().signed_caller_identity(_identity(), GCP_AUDIENCE)

        assert "fed-secret" not in urllib.parse.unquote(token)

    @pytest.mark.asyncio
    async def test_omits_the_session_token_header_for_long_lived_keys(self):
        identity = replace(
            _identity(),
            credentials=AwsCredentials(access_key_id="AKIAFED", secret_access_key="s"),
        )

        token = await _regional_sts().signed_caller_identity(identity, GCP_AUDIENCE)

        _, headers = _decode_subject_token(token)
        assert "x-amz-security-token" not in headers

    @pytest.mark.asyncio
    async def test_names_the_sdk_region_not_the_configured_endpoint(self):
        token = await _regional_sts("us-west-2").signed_caller_identity(
            _identity(), GCP_AUDIENCE
        )

        request, headers = _decode_subject_token(token)
        assert request["url"].startswith("https://sts.us-west-2.amazonaws.com?")
        assert "/us-west-2/sts/aws4_request," in headers["authorization"]

    @pytest.mark.asyncio
    async def test_requires_a_configured_region(self):
        with pytest.raises(ConfigurationError):
            await _regional_sts(region=None).signed_caller_identity(
                _identity(), GCP_AUDIENCE
            )


def _recording_client(
    handler: Callable[[httpx.Request], httpx.Response] | Exception,
) -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    """An in-memory HTTP client; returns (client, requests it received)."""
    requests: list[httpx.Request] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if isinstance(handler, Exception):
            raise handler
        return handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(transport_handler)), requests


def _exchange(
    handler: Callable[[httpx.Request], httpx.Response] | Exception,
) -> tuple[AnthropicTokenExchange, list[httpx.Request]]:
    """An Anthropic adapter over an in-memory transport; returns (adapter, requests)."""
    client, requests = _recording_client(handler)
    return AnthropicTokenExchange(http_client=client), requests


def _openai_exchange(
    handler: Callable[[httpx.Request], httpx.Response] | Exception,
) -> tuple[OpenAiTokenExchange, list[httpx.Request]]:
    """An OpenAI adapter over an in-memory transport; returns (adapter, requests)."""
    client, requests = _recording_client(handler)
    return OpenAiTokenExchange(http_client=client), requests


def _openrouter_exchange(
    handler: Callable[[httpx.Request], httpx.Response] | Exception,
) -> tuple[OpenRouterTokenExchange, list[httpx.Request]]:
    """An OpenRouter adapter over an in-memory transport."""
    client, requests = _recording_client(handler)
    return OpenRouterTokenExchange(http_client=client), requests


def _token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": "sk-ant-oat01-example", "expires_in": 3600}
    )


class TestAnthropicTokenExchange:
    @pytest.mark.asyncio
    async def test_posts_jwt_bearer_grant_and_returns_token(self):
        adapter, requests = _exchange(_token_response)
        before = datetime.now(timezone.utc)

        minted = await adapter.exchange("header.payload.signature", _secret())

        (request,) = requests
        assert request.method == "POST"
        assert str(request.url) == "https://api.example.com/v1/oauth/token"
        assert json.loads(request.content) == {
            "grant_type": JWT_BEARER_GRANT_TYPE,
            "assertion": "header.payload.signature",
            "federation_rule_id": "fr_example",
            "organization_id": "org_example",
            "service_account_id": "sa_example",
            "workspace_id": "ws_example",
        }
        assert minted.token == "sk-ant-oat01-example"
        assert before + timedelta(seconds=3600) <= minted.expires_at
        assert minted.expires_at <= datetime.now(timezone.utc) + timedelta(seconds=3600)

    @pytest.mark.asyncio
    async def test_error_status_raises_without_leaking_the_assertion(self):
        adapter, _ = _exchange(
            lambda request: httpx.Response(401, json={"error": "invalid_grant"})
        )

        with pytest.raises(AuthenticationError, match="HTTP 401") as exc_info:
            await adapter.exchange("secret.jwt.value", _secret())

        assert "secret.jwt.value" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_malformed_body_raises(self):
        adapter, _ = _exchange(lambda request: httpx.Response(200, json={"ok": 1}))

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange("header.payload.signature", _secret())

    @pytest.mark.asyncio
    async def test_transport_failure_raises_upstream_service_error(self):
        adapter, _ = _exchange(httpx.ConnectError("connection refused"))

        with pytest.raises(UpstreamServiceError, match="unavailable"):
            await adapter.exchange("header.payload.signature", _secret())

    @pytest.mark.parametrize("status", [500, 503, 429])
    @pytest.mark.asyncio
    async def test_server_errors_and_rate_limits_raise_upstream_service_error(
        self, status: int
    ):
        adapter, _ = _exchange(lambda request: httpx.Response(status, text="busy"))

        with pytest.raises(UpstreamServiceError, match=f"HTTP {status}"):
            await adapter.exchange("header.payload.signature", _secret())


# The documented response shape; fields other than access_token and
# expires_in are ignored.
OPENAI_TOKEN_RESPONSE = {
    "access_token": "eyJ.openai.example",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 900,
    "expires_at": 1767273300,
    "scope": "api.model.request",
}


def _openai_token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=OPENAI_TOKEN_RESPONSE)


class TestOpenAiTokenExchange:
    @pytest.mark.asyncio
    async def test_posts_a_token_exchange_and_returns_the_access_token(self):
        adapter, requests = _openai_exchange(_openai_token_response)
        before = datetime.now(timezone.utc)

        minted = await adapter.exchange("header.payload.signature", _openai_secret())

        (request,) = requests
        assert request.method == "POST"
        assert str(request.url) == OPENAI_TOKEN_URL
        assert request.headers["content-type"] == "application/json"
        assert "authorization" not in request.headers
        assert json.loads(request.content) == {
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token_type": JWT_TOKEN_TYPE,
            "subject_token": "header.payload.signature",
            "identity_provider_id": "idp_example",
            "service_account_id": "svc_acct_example",
        }
        assert minted.token == "eyJ.openai.example"
        assert before + timedelta(seconds=900) <= minted.expires_at
        assert minted.expires_at <= datetime.now(timezone.utc) + timedelta(seconds=900)

    @pytest.mark.asyncio
    async def test_exchange_url_does_not_depend_on_the_secret_host(self):
        adapter, requests = _openai_exchange(_openai_token_response)

        await adapter.exchange(
            "header.payload.signature", _openai_secret(host="api.example.com")
        )

        (request,) = requests
        assert str(request.url) == OPENAI_TOKEN_URL

    @pytest.mark.parametrize("status", [400, 401, 403])
    @pytest.mark.asyncio
    async def test_rejection_raises_without_leaking_the_token(
        self, status: int, caplog
    ):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _openai_exchange(
            lambda request: httpx.Response(status, json={"error": "invalid_grant"})
        )

        with pytest.raises(AuthenticationError, match=f"HTTP {status}") as exc_info:
            await adapter.exchange("secret.jwt.value", _openai_secret())

        assert "invalid_grant" in caplog.text
        assert "secret.jwt.value" not in str(exc_info.value)
        assert "secret.jwt.value" not in caplog.text

    @pytest.mark.parametrize("status", [500, 503, 429])
    @pytest.mark.asyncio
    async def test_server_errors_and_rate_limits_raise_upstream_service_error(
        self, status: int
    ):
        adapter, _ = _openai_exchange(
            lambda request: httpx.Response(status, text="busy")
        )

        with pytest.raises(UpstreamServiceError, match=f"HTTP {status}"):
            await adapter.exchange("header.payload.signature", _openai_secret())

    @pytest.mark.asyncio
    async def test_transport_failure_raises_upstream_service_error(self, caplog):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _openai_exchange(httpx.ConnectError("connection refused"))

        with pytest.raises(UpstreamServiceError, match="unavailable") as exc_info:
            await adapter.exchange("secret.jwt.value", _openai_secret())

        assert exc_info.value.__cause__ is None
        assert "ConnectError: connection refused" in caplog.text
        assert "secret.jwt.value" not in caplog.text

    @pytest.mark.parametrize(
        "body",
        [
            {"ok": 1},
            {"expires_in": 900},
            {"access_token": "", "expires_in": 900},
            {"access_token": "eyJ.openai.example"},
            {"access_token": "eyJ.openai.example", "expires_in": "soon"},
            {"access_token": "eyJ.openai.example", "expires_in": 0},
            {"access_token": "eyJ.openai.example", "expires_in": -900},
        ],
    )
    @pytest.mark.asyncio
    async def test_response_without_a_usable_token_raises(self, body: dict, caplog):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _openai_exchange(lambda request: httpx.Response(200, json=body))

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange("header.payload.signature", _openai_secret())

        assert "malformed body" in caplog.text
        assert "eyJ.openai.example" not in caplog.text

    @pytest.mark.asyncio
    async def test_non_json_success_body_raises(self):
        adapter, _ = _openai_exchange(
            lambda request: httpx.Response(200, content=b"<html>upstream</html>")
        )

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange("header.payload.signature", _openai_secret())


class TestOAuthTokenResponse:
    def test_ignores_fields_beyond_the_token_and_its_lifetime(self):
        parsed = OAuthTokenResponse.model_validate(OPENAI_TOKEN_RESPONSE)

        assert parsed.access_token == "eyJ.openai.example"
        assert parsed.expires_in == 900

    def test_accepts_a_numeric_string_lifetime(self):
        parsed = OAuthTokenResponse.model_validate(
            {"access_token": "token", "expires_in": "900"}
        )

        assert parsed.expires_in == 900

    def test_minted_token_expires_relative_to_the_request_time(self):
        parsed = OAuthTokenResponse.model_validate(
            {"access_token": "token", "expires_in": 900}
        )

        assert parsed.minted_token(NOW) == MintedToken(
            token="token", expires_at=NOW + timedelta(seconds=900)
        )


# The documented response shape; fields other than access_token and
# expires_in are ignored.
OPENROUTER_TOKEN_RESPONSE = {
    "access_token": "eyJ.openrouter.example",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "inference",
}


def _openrouter_token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=OPENROUTER_TOKEN_RESPONSE)


def _form_fields(request: httpx.Request) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(request.content.decode(), strict_parsing=True)


class TestOpenRouterTokenExchange:
    @pytest.mark.asyncio
    async def test_posts_a_form_token_exchange_and_returns_the_access_token(self):
        adapter, requests = _openrouter_exchange(_openrouter_token_response)
        before = datetime.now(timezone.utc)

        minted = await adapter.exchange(
            "header.payload.signature", _openrouter_secret()
        )

        (request,) = requests
        assert request.method == "POST"
        assert str(request.url) == OPENROUTER_TOKEN_URL
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        assert "authorization" not in request.headers
        assert _form_fields(request) == {
            "grant_type": [TOKEN_EXCHANGE_GRANT_TYPE],
            "subject_token_type": [JWT_TOKEN_TYPE],
            "subject_token": ["header.payload.signature"],
            "federation_policy_id": ["fedpol_example"],
        }
        assert minted.token == "eyJ.openrouter.example"
        assert before + timedelta(seconds=900) <= minted.expires_at
        assert minted.expires_at <= datetime.now(timezone.utc) + timedelta(seconds=900)

    @pytest.mark.asyncio
    async def test_exchange_url_does_not_depend_on_the_secret_host(self):
        adapter, requests = _openrouter_exchange(_openrouter_token_response)

        await adapter.exchange(
            "header.payload.signature", _openrouter_secret(host="api.example.com")
        )

        (request,) = requests
        assert str(request.url) == OPENROUTER_TOKEN_URL

    @pytest.mark.parametrize("status", [400, 401, 403])
    @pytest.mark.asyncio
    async def test_rejection_raises_without_leaking_the_token(
        self, status: int, caplog
    ):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _openrouter_exchange(
            lambda request: httpx.Response(status, json={"error": "invalid_grant"})
        )

        with pytest.raises(AuthenticationError, match=f"HTTP {status}") as exc_info:
            await adapter.exchange("secret.jwt.value", _openrouter_secret())

        assert "invalid_grant" in caplog.text
        assert "secret.jwt.value" not in str(exc_info.value)
        assert "secret.jwt.value" not in caplog.text

    @pytest.mark.parametrize("status", [500, 503, 429])
    @pytest.mark.asyncio
    async def test_server_errors_and_rate_limits_raise_upstream_service_error(
        self, status: int
    ):
        adapter, _ = _openrouter_exchange(
            lambda request: httpx.Response(
                status, headers={"Retry-After": "1"}, json={"error": "invalid_request"}
            )
        )

        with pytest.raises(UpstreamServiceError, match=f"HTTP {status}"):
            await adapter.exchange("header.payload.signature", _openrouter_secret())

    @pytest.mark.asyncio
    async def test_transport_failure_raises_upstream_service_error(self, caplog):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _openrouter_exchange(httpx.ConnectError("connection refused"))

        with pytest.raises(UpstreamServiceError, match="unavailable") as exc_info:
            await adapter.exchange("secret.jwt.value", _openrouter_secret())

        assert exc_info.value.__cause__ is None
        assert "ConnectError: connection refused" in caplog.text
        assert "secret.jwt.value" not in caplog.text

    @pytest.mark.asyncio
    async def test_response_without_a_usable_token_raises(self):
        adapter, _ = _openrouter_exchange(
            lambda request: httpx.Response(200, json={"token_type": "Bearer"})
        )

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange("header.payload.signature", _openrouter_secret())


GOOGLE_STS_RESPONSE = {
    "access_token": "federated-token",
    "issued_token_type": GOOGLE_ACCESS_TOKEN_TYPE,
    "token_type": "Bearer",
    "expires_in": 3600,
}
GOOGLE_IAM_RESPONSE = {
    "accessToken": "ya29.example",
    "expireTime": "2026-01-01T13:00:00Z",
}


def _google(
    sts: httpx.Response | Exception | None = None,
    iam: httpx.Response | Exception | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """A handler for Google's STS and IAM Credentials endpoints."""

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_STS_TOKEN_URL:
            outcome = (
                sts
                if sts is not None
                else httpx.Response(200, json=GOOGLE_STS_RESPONSE)
            )
        elif str(request.url) == GCP_IAM_URL:
            outcome = (
                iam
                if iam is not None
                else httpx.Response(200, json=GOOGLE_IAM_RESPONSE)
            )
        else:
            raise AssertionError(f"unexpected request to {request.url}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return handler


def _gcp_exchange(
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[GcpTokenExchange, list[tuple[int, httpx.Request]]]:
    """A GCP adapter over an in-memory transport.

    Returns (adapter, [(thread ident, request)]).
    """
    requests: list[tuple[int, httpx.Request]] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        requests.append((threading.get_ident(), request))
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))
    return GcpTokenExchange(http_client=client), requests


def _sts_form(request: httpx.Request) -> dict[str, str]:
    form = urllib.parse.parse_qs(request.content.decode(), strict_parsing=True)
    assert all(len(values) == 1 for values in form.values())
    return {key: values[0] for key, values in form.items()}


class TestGcpTokenExchange:
    @pytest.mark.parametrize(
        ("identity_proof", "subject_token_type"),
        [("oidc", JWT_TOKEN_TYPE), ("aws_sigv4", AWS_SUBJECT_TOKEN_TYPE)],
    )
    @pytest.mark.asyncio
    async def test_exchanges_the_identity_proof_and_impersonates(
        self, identity_proof: str, subject_token_type: str
    ):
        adapter, requests = _gcp_exchange(_google())

        minted = await adapter.exchange(
            PROOF, _gcp_secret(identity_proof=identity_proof)
        )

        (_, sts_request), (_, iam_request) = requests
        assert sts_request.method == "POST"
        assert _sts_form(sts_request) == {
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "audience": GCP_AUDIENCE,
            "scope": GOOGLE_IAM_SCOPE,
            "requested_token_type": GOOGLE_ACCESS_TOKEN_TYPE,
            "subject_token_type": subject_token_type,
            "subject_token": PROOF,
        }

        assert iam_request.method == "POST"
        assert iam_request.headers["authorization"] == "Bearer federated-token"
        assert json.loads(iam_request.content) == {
            "scope": [GCP_CLOUD_PLATFORM_SCOPE],
            "lifetime": "3600s",
        }
        assert minted == MintedToken(
            token="ya29.example",
            expires_at=datetime(2026, 1, 1, 13, 0, tzinfo=timezone.utc),
        )

    @pytest.mark.asyncio
    async def test_requests_run_on_the_event_loop_thread(self):
        # The app's X-Ray context is task-local; a worker thread would have
        # no segment (or another task's) for the instrumented HTTP client.
        adapter, requests = _gcp_exchange(_google())

        await adapter.exchange(PROOF, _gcp_secret())

        assert {thread for thread, _ in requests} == {threading.get_ident()}

    @pytest.mark.asyncio
    async def test_scopes_and_lifetime_come_from_the_secret(self):
        adapter, requests = _gcp_exchange(_google())
        secret = _gcp_secret(
            scopes=[
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/generative-language",
            ],
            token_lifetime_seconds=900,
        )

        await adapter.exchange(PROOF, secret)

        (_, iam_request) = requests[1]
        body = json.loads(iam_request.content)
        assert body["scope"] == secret.scopes
        assert body["lifetime"] == "900s"

    @pytest.mark.asyncio
    async def test_fractional_expire_time_is_parsed(self):
        adapter, _ = _gcp_exchange(
            _google(
                iam=httpx.Response(
                    200,
                    json={
                        "accessToken": "ya29.example",
                        "expireTime": "2026-01-01T13:00:00.123456789Z",
                    },
                )
            )
        )

        minted = await adapter.exchange(PROOF, _gcp_secret())

        assert minted.expires_at == datetime(
            2026, 1, 1, 13, 0, 0, 123456, tzinfo=timezone.utc
        )

    @pytest.mark.parametrize("identity_proof", ["oidc", "aws_sigv4"])
    @pytest.mark.asyncio
    async def test_sts_rejection_raises_without_leaking_credentials(
        self, identity_proof: str, caplog
    ):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, requests = _gcp_exchange(
            _google(
                sts=httpx.Response(
                    400,
                    json={"error": "invalid_grant", "error_description": "denied"},
                )
            )
        )

        with pytest.raises(AuthenticationError, match="HTTP 400") as exc_info:
            await adapter.exchange(PROOF, _gcp_secret(identity_proof=identity_proof))

        assert len(requests) == 1
        assert "invalid_grant" in caplog.text
        assert PROOF not in str(exc_info.value)
        assert PROOF not in caplog.text

    @pytest.mark.asyncio
    async def test_impersonation_rejection_raises_without_leaking_tokens(self, caplog):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, requests = _gcp_exchange(
            _google(iam=httpx.Response(403, json={"error": {"code": 403}}))
        )

        with pytest.raises(AuthenticationError, match="HTTP 403") as exc_info:
            await adapter.exchange(PROOF, _gcp_secret())

        assert len(requests) == 2
        assert "federated-token" not in str(exc_info.value)
        assert "federated-token" not in caplog.text

    @pytest.mark.asyncio
    async def test_client_timeouts_fit_the_mint_deadline(self):
        adapter = GcpTokenExchange()
        try:
            assert adapter.http_client.timeout == httpx.Timeout(3.0, connect=1.0)
        finally:
            await adapter.aclose()

    @pytest.mark.asyncio
    async def test_service_account_is_url_quoted_in_the_impersonation_url(self):
        urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == GOOGLE_STS_TOKEN_URL:
                return httpx.Response(200, json=GOOGLE_STS_RESPONSE)
            urls.append(str(request.url))
            return httpx.Response(200, json=GOOGLE_IAM_RESPONSE)

        adapter, _ = _gcp_exchange(handler)

        await adapter.exchange(PROOF, _gcp_secret(service_account="sa+x@example.com"))

        assert urls == [
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            "sa%2Bx@example.com:generateAccessToken"
        ]

    @pytest.mark.asyncio
    async def test_transport_failure_raises_upstream_service_error(self, caplog):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _gcp_exchange(_google(sts=httpx.ConnectError("refused")))

        with pytest.raises(UpstreamServiceError, match="unavailable") as exc_info:
            await adapter.exchange(PROOF, _gcp_secret())

        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__
        assert "ConnectError: refused" in caplog.text
        assert PROOF not in caplog.text

    @pytest.mark.parametrize("status", [500, 503, 429])
    @pytest.mark.asyncio
    async def test_server_errors_and_rate_limits_raise_upstream_service_error(
        self, status: int
    ):
        adapter, requests = _gcp_exchange(
            _google(iam=httpx.Response(status, text="busy"))
        )

        with pytest.raises(UpstreamServiceError, match=f"HTTP {status}"):
            await adapter.exchange(PROOF, _gcp_secret())

        assert len(requests) == 2

    @pytest.mark.asyncio
    async def test_empty_federated_token_stops_before_impersonation(self):
        adapter, requests = _gcp_exchange(
            _google(sts=httpx.Response(200, json={"access_token": ""}))
        )

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange(PROOF, _gcp_secret())

        assert len(requests) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body",
        [
            {"expireTime": "2026-01-01T13:00:00Z"},
            {"accessToken": "", "expireTime": "2026-01-01T13:00:00Z"},
            {"accessToken": "ya29.example"},
            {"accessToken": "ya29.example", "expireTime": "soon"},
            {"accessToken": "ya29.example", "expireTime": "2026-01-01T13:00:00"},
        ],
    )
    async def test_impersonation_response_without_a_usable_token_raises(
        self, body: dict, caplog
    ):
        caplog.set_level(logging.ERROR, logger="api.access")
        adapter, _ = _gcp_exchange(_google(iam=httpx.Response(200, json=body)))

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange(PROOF, _gcp_secret())

        assert "ya29.example" not in caplog.text

    @pytest.mark.asyncio
    async def test_non_json_success_body_raises(self):
        adapter, _ = _gcp_exchange(
            _google(sts=httpx.Response(200, content=b"<html>upstream</html>"))
        )

        with pytest.raises(AuthenticationError, match="malformed"):
            await adapter.exchange(PROOF, _gcp_secret())


class TestTokenMintService:
    def _service(
        self,
    ) -> tuple[TokenMintService, MagicMock, MagicMock, MagicMock, MagicMock, MagicMock]:
        sts = MagicMock()
        sts.assume_federation_role = AsyncMock(return_value=_identity())
        sts.signed_caller_identity = AsyncMock(return_value=PROOF)
        tokens = iter(["jwt-1", "jwt-2", "jwt-3"])
        sts.web_identity_token = AsyncMock(
            side_effect=lambda *args, **kwargs: WebIdentityToken(
                token=next(tokens), expires_at=NOW + timedelta(minutes=15)
            )
        )
        anthropic = MagicMock()
        anthropic.exchange = AsyncMock(
            side_effect=lambda proof, secret: MintedToken(
                token=f"token-for-{proof}", expires_at=NOW + timedelta(hours=1)
            )
        )
        gcp = MagicMock()
        gcp.exchange = AsyncMock(
            return_value=MintedToken(
                token="ya29.example", expires_at=NOW + timedelta(hours=1)
            )
        )
        openai = MagicMock()
        openai.exchange = AsyncMock(
            side_effect=lambda proof, secret: MintedToken(
                token=f"openai-token-for-{proof}", expires_at=NOW + timedelta(hours=1)
            )
        )
        openrouter = MagicMock()
        openrouter.exchange = AsyncMock(
            side_effect=lambda proof, secret: MintedToken(
                token=f"openrouter-token-for-{proof}",
                expires_at=NOW + timedelta(minutes=15),
            )
        )
        return (
            TokenMintService(
                sts=sts,
                anthropic=anthropic,
                gcp=gcp,
                openai=openai,
                openrouter=openrouter,
                federation_config=FEDERATION_CONFIG,
            ),
            sts,
            anthropic,
            gcp,
            openai,
            openrouter,
        )

    @pytest.mark.asyncio
    async def test_aclose_closes_every_adapter_client(self):
        service = TokenMintService(
            boto_session=MagicMock(), federation_config=FEDERATION_CONFIG
        )
        clients = [
            service.anthropic.http_client,
            service.openai.http_client,
            service.gcp.http_client,
            service.openrouter.http_client,
        ]

        await service.aclose()

        assert all(client.is_closed for client in clients)

    def test_boto_session_is_shared_with_the_sts_service(self):
        session = MagicMock()

        service = TokenMintService(
            boto_session=session, federation_config=FEDERATION_CONFIG
        )

        assert service.sts.boto_session is session

    @pytest.mark.asyncio
    async def test_mint_sequences_proof_and_exchange(self):
        service, sts, anthropic, _, _, _ = self._service()
        secret = _secret()

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_awaited_once_with(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )
        sts.web_identity_token.assert_awaited_once_with(
            _identity(), "https://api.anthropic.com"
        )
        anthropic.exchange.assert_awaited_once_with("jwt-1", secret)
        sts.signed_caller_identity.assert_not_awaited()
        assert minted.token == "token-for-jwt-1"

    @pytest.mark.asyncio
    async def test_mint_stops_at_the_deadline(self, monkeypatch):
        service, sts, anthropic, gcp, _, _ = self._service()

        async def slow_assume(*args, **kwargs):
            await asyncio.sleep(1)
            return _identity()

        sts.assume_federation_role = AsyncMock(side_effect=slow_assume)
        monkeypatch.setattr(federation_service, "MINT_DEADLINE_SECONDS", 0.01)

        with pytest.raises(UpstreamServiceError, match="timed out"):
            await service.mint(CALLER_CREDENTIALS, CALLER, _secret())

        sts.web_identity_token.assert_not_awaited()
        sts.signed_caller_identity.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        gcp.exchange.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_gcp_mint_requests_an_rs256_token_for_the_pool_provider(self):
        service, sts, anthropic, gcp, _, _ = self._service()
        secret = _gcp_secret()

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_awaited_once_with(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )
        # The defaults: RS256 and IDENTITY_TOKEN_SECONDS, as for anthropic_wif.
        sts.web_identity_token.assert_awaited_once_with(_identity(), GCP_AUDIENCE)
        gcp.exchange.assert_awaited_once_with("jwt-1", secret)
        sts.signed_caller_identity.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        assert minted.token == "ya29.example"

    @pytest.mark.asyncio
    async def test_gcp_sigv4_mint_signs_the_caller_identity_and_exchanges(self):
        service, sts, anthropic, gcp, _, _ = self._service()
        secret = _gcp_secret(identity_proof="aws_sigv4")

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_awaited_once_with(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )
        sts.signed_caller_identity.assert_awaited_once_with(_identity(), GCP_AUDIENCE)
        gcp.exchange.assert_awaited_once_with(PROOF, secret)
        sts.web_identity_token.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        assert minted.token == "ya29.example"

    @pytest.mark.asyncio
    async def test_openai_mint_requests_an_es384_token_for_the_openai_audience(
        self,
    ):
        service, sts, anthropic, gcp, openai, openrouter = self._service()
        secret = _openai_secret()

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_awaited_once_with(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )
        sts.web_identity_token.assert_awaited_once_with(
            _identity(),
            OPENAI_API_AUDIENCE,
            OPENAI_IDENTITY_TOKEN_SIGNING_ALGORITHM,
            OPENAI_IDENTITY_TOKEN_SECONDS,
        )
        assert OPENAI_IDENTITY_TOKEN_SIGNING_ALGORITHM == "ES384"
        assert OPENAI_IDENTITY_TOKEN_SECONDS == 1800
        openai.exchange.assert_awaited_once_with("jwt-1", secret)
        sts.signed_caller_identity.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        gcp.exchange.assert_not_awaited()
        openrouter.exchange.assert_not_awaited()
        assert minted.token == "openai-token-for-jwt-1"

    @pytest.mark.asyncio
    async def test_openai_audience_comes_from_the_secret(self):
        service, sts, _, _, _, _ = self._service()

        await service.mint(
            CALLER_CREDENTIALS, CALLER, _openai_secret(audience="https://example.com")
        )

        sts.web_identity_token.assert_awaited_once_with(
            _identity(), "https://example.com", "ES384", 1800
        )

    @pytest.mark.asyncio
    async def test_openrouter_mint_requests_an_rs256_token_for_the_openrouter_audience(
        self,
    ):
        service, sts, anthropic, gcp, openai, openrouter = self._service()
        secret = _openrouter_secret()

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_awaited_once_with(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )
        sts.web_identity_token.assert_awaited_once_with(
            _identity(),
            OPENROUTER_API_AUDIENCE,
            OPENROUTER_IDENTITY_TOKEN_SIGNING_ALGORITHM,
            OPENROUTER_IDENTITY_TOKEN_SECONDS,
        )
        assert OPENROUTER_IDENTITY_TOKEN_SIGNING_ALGORITHM == "RS256"
        assert OPENROUTER_IDENTITY_TOKEN_SECONDS == 900
        openrouter.exchange.assert_awaited_once_with("jwt-1", secret)
        sts.signed_caller_identity.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        gcp.exchange.assert_not_awaited()
        openai.exchange.assert_not_awaited()
        assert minted.token == "openrouter-token-for-jwt-1"

    @pytest.mark.asyncio
    async def test_openrouter_audience_comes_from_the_secret(self):
        service, sts, _, _, _, _ = self._service()

        await service.mint(
            CALLER_CREDENTIALS,
            CALLER,
            _openrouter_secret(audience="https://example.com"),
        )

        sts.web_identity_token.assert_awaited_once_with(
            _identity(), "https://example.com", "RS256", 900
        )

    @pytest.mark.asyncio
    async def test_gcp_sigv4_mint_propagates_a_missing_region(self):
        service, sts, _, gcp, _, _ = self._service()
        sts.signed_caller_identity = AsyncMock(
            side_effect=ConfigurationError("no region")
        )

        with pytest.raises(ConfigurationError):
            await service.mint(
                CALLER_CREDENTIALS, CALLER, _gcp_secret(identity_proof="aws_sigv4")
            )

        gcp.exchange.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_anthropic_mint_end_to_end(self):
        session, clients = _sts_session(
            assume_role=ASSUME_ROLE_RESPONSE,
            get_web_identity_token=WEB_IDENTITY_RESPONSE,
        )
        anthropic, requests = _exchange(_token_response)
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            anthropic=anthropic,
            federation_config=FEDERATION_CONFIG,
        )

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, _secret())

        assume, web_identity = clients
        assume.assume_role.assert_awaited_once()
        assert web_identity.create_kwargs["aws_session_token"] == "fed-token"
        web_identity_kwargs = web_identity.get_web_identity_token.await_args.kwargs
        assert web_identity_kwargs["SigningAlgorithm"] == "RS256"
        assert web_identity_kwargs["DurationSeconds"] == IDENTITY_TOKEN_SECONDS
        (request,) = requests
        assert json.loads(request.content)["assertion"] == "header.payload.signature"
        assert minted.token == "sk-ant-oat01-example"

    @pytest.mark.asyncio
    async def test_openai_mint_end_to_end(self):
        session, clients = _sts_session(
            assume_role=ASSUME_ROLE_RESPONSE,
            get_web_identity_token=WEB_IDENTITY_RESPONSE,
        )
        openai, requests = _openai_exchange(_openai_token_response)
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            openai=openai,
            federation_config=FEDERATION_CONFIG,
        )

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, _openai_secret())

        assume, web_identity = clients
        assume.assume_role.assert_awaited_once()
        assert web_identity.create_kwargs["aws_session_token"] == "fed-token"
        web_identity.get_web_identity_token.assert_awaited_once_with(
            Audience=[OPENAI_API_AUDIENCE],
            SigningAlgorithm="ES384",
            DurationSeconds=OPENAI_IDENTITY_TOKEN_SECONDS,
            Tags=[
                {"Key": "portunus:user", "Value": CALLER_ROLE},
                {"Key": "portunus:principal", "Value": CALLER_ROLE},
                {"Key": "portunus:session", "Value": "session"},
                {"Key": "portunus:project", "Value": "example"},
            ],
        )
        (request,) = requests
        assert str(request.url) == OPENAI_TOKEN_URL
        assert (
            json.loads(request.content)["subject_token"] == "header.payload.signature"
        )
        assert minted.token == "eyJ.openai.example"

    @pytest.mark.asyncio
    async def test_openrouter_mint_end_to_end(self):
        session, clients = _sts_session(
            assume_role=ASSUME_ROLE_RESPONSE,
            get_web_identity_token=WEB_IDENTITY_RESPONSE,
        )
        openrouter, requests = _openrouter_exchange(_openrouter_token_response)
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            openrouter=openrouter,
            federation_config=FEDERATION_CONFIG,
        )

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, _openrouter_secret())

        assume, web_identity = clients
        assume.assume_role.assert_awaited_once()
        assert web_identity.create_kwargs["aws_session_token"] == "fed-token"
        web_identity.get_web_identity_token.assert_awaited_once_with(
            Audience=[OPENROUTER_API_AUDIENCE],
            SigningAlgorithm="RS256",
            DurationSeconds=OPENROUTER_IDENTITY_TOKEN_SECONDS,
            Tags=[
                {"Key": "portunus:user", "Value": CALLER_ROLE},
                {"Key": "portunus:principal", "Value": CALLER_ROLE},
                {"Key": "portunus:session", "Value": "session"},
                {"Key": "portunus:project", "Value": "example"},
            ],
        )
        (request,) = requests
        assert str(request.url) == OPENROUTER_TOKEN_URL
        assert _form_fields(request)["subject_token"] == ["header.payload.signature"]
        assert minted.token == "eyJ.openrouter.example"

    @pytest.mark.asyncio
    async def test_gcp_oidc_mint_end_to_end(self):
        session, clients = _sts_session(
            assume_role=ASSUME_ROLE_RESPONSE,
            get_web_identity_token=WEB_IDENTITY_RESPONSE,
        )
        gcp, requests = _gcp_exchange(_google())
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            gcp=gcp,
            federation_config=FEDERATION_CONFIG,
        )

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, _gcp_secret())

        assume, web_identity = clients
        assume.assume_role.assert_awaited_once()
        assert web_identity.create_kwargs["aws_session_token"] == "fed-token"
        web_identity.get_web_identity_token.assert_awaited_once_with(
            Audience=[GCP_AUDIENCE],
            SigningAlgorithm="RS256",
            DurationSeconds=IDENTITY_TOKEN_SECONDS,
            Tags=[
                {"Key": "portunus:user", "Value": CALLER_ROLE},
                {"Key": "portunus:principal", "Value": CALLER_ROLE},
                {"Key": "portunus:session", "Value": "session"},
                {"Key": "portunus:project", "Value": "example"},
            ],
        )
        # No signed request, so no region lookup.
        session.get_config_variable.assert_not_called()
        (_, sts_request), _ = requests
        form = _sts_form(sts_request)
        assert form["subject_token_type"] == JWT_TOKEN_TYPE
        assert form["subject_token"] == "header.payload.signature"
        assert minted.token == "ya29.example"

    @pytest.mark.asyncio
    async def test_gcp_oidc_mint_stops_when_sts_denies_the_identity_token(self):
        session, clients = _sts_session(
            assume_role=ASSUME_ROLE_RESPONSE,
            get_web_identity_token=_client_error("AccessDenied", "GetWebIdentityToken"),
        )
        gcp, requests = _gcp_exchange(_google())
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            gcp=gcp,
            federation_config=FEDERATION_CONFIG,
        )

        with pytest.raises(AuthenticationError, match="identity token \\(AccessDenied"):
            await service.mint(CALLER_CREDENTIALS, CALLER, _gcp_secret())

        _, web_identity = clients
        web_identity.get_web_identity_token.assert_awaited_once()
        assert requests == []

    @pytest.mark.asyncio
    async def test_gcp_oidc_mint_maps_a_google_refusal_to_authentication_error(
        self, caplog
    ):
        caplog.set_level(logging.ERROR, logger="api.access")
        session, _ = _sts_session(
            assume_role=ASSUME_ROLE_RESPONSE,
            get_web_identity_token=WEB_IDENTITY_RESPONSE,
        )
        gcp, requests = _gcp_exchange(
            _google(sts=httpx.Response(400, json={"error": "invalid_grant"}))
        )
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            gcp=gcp,
            federation_config=FEDERATION_CONFIG,
        )

        with pytest.raises(AuthenticationError, match="HTTP 400") as exc_info:
            await service.mint(CALLER_CREDENTIALS, CALLER, _gcp_secret())

        assert len(requests) == 1
        assert "invalid_grant" in caplog.text
        assert "header.payload.signature" not in str(exc_info.value)
        assert "header.payload.signature" not in caplog.text

    @pytest.mark.asyncio
    async def test_gcp_sigv4_mint_end_to_end(self):
        session, clients = _sts_session(assume_role=ASSUME_ROLE_RESPONSE)
        session.get_config_variable = MagicMock(return_value=REGION)
        gcp, requests = _gcp_exchange(_google())
        service = TokenMintService(
            sts=StsFederationService(session, FEDERATION_CONFIG),
            gcp=gcp,
            federation_config=FEDERATION_CONFIG,
        )

        minted = await service.mint(
            CALLER_CREDENTIALS, CALLER, _gcp_secret(identity_proof="aws_sigv4")
        )

        (assume,) = clients
        assume.get_web_identity_token.assert_not_awaited()
        (_, sts_request), _ = requests
        form = _sts_form(sts_request)
        assert form["subject_token_type"] == AWS_SUBJECT_TOKEN_TYPE
        request, headers = _decode_subject_token(form["subject_token"])
        assert request["url"].startswith(f"https://sts.{REGION}.amazonaws.com?")
        assert headers["x-amz-security-token"] == "fed-token"
        assert headers["x-goog-cloud-target-resource"] == GCP_AUDIENCE
        assert "fed-secret" not in sts_request.content.decode()
        assert minted.token == "ya29.example"

    @pytest.mark.asyncio
    async def test_each_mint_uses_a_fresh_identity_token(self):
        service, sts, anthropic, _, _, _ = self._service()

        first = await service.mint(CALLER_CREDENTIALS, CALLER, _secret())
        second = await service.mint(CALLER_CREDENTIALS, CALLER, _secret())

        assert sts.web_identity_token.await_count == 2
        assert [call.args[0] for call in anthropic.exchange.await_args_list] == [
            "jwt-1",
            "jwt-2",
        ]
        assert first.token != second.token

    @pytest.mark.asyncio
    async def test_disallowed_role_is_rejected_before_any_aws_call(self):
        service, sts, anthropic, gcp, openai, openrouter = self._service()
        secret = _secret(
            federation_role_arn=(
                f"arn:aws:iam::{OTHER_ACCOUNT}:role/portunus-fed/projects/example/name"
            )
        )

        with pytest.raises(AuthenticationError, match="allowed account"):
            await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_not_awaited()
        sts.web_identity_token.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        gcp.exchange.assert_not_awaited()
        openai.exchange.assert_not_awaited()
        openrouter.exchange.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unknown_mint_type_has_no_exchange(self):
        class OtherSecret(MintSecretBase):
            type: Literal["other"] = "other"

        service, sts, anthropic, gcp, openai, openrouter = self._service()
        secret = OtherSecret(host="api.example.com", federation_role_arn=ROLE_ARN)

        with pytest.raises(AuthenticationError, match="OtherSecret"):
            await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
        gcp.exchange.assert_not_awaited()
        openai.exchange.assert_not_awaited()
        openrouter.exchange.assert_not_awaited()
