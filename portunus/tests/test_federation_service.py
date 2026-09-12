"""Tests for minting short-lived upstream tokens via federation roles."""

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Literal
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from botocore.exceptions import ClientError

from portunus.config import FederationConfig
from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
)
from portunus.models import (
    AnthropicWifSecret,
    AwsCredentials,
    MintSecretBase,
    PrincipalInfo,
)
from portunus.services.federation_service import (
    FEDERATION_SESSION_SECONDS,
    IDENTITY_TOKEN_SECONDS,
    JWT_BEARER_GRANT_TYPE,
    AnthropicTokenExchange,
    FederationIdentity,
    MintedToken,
    StsFederationService,
    TokenMintService,
    WebIdentityToken,
    caller_project,
    caller_role_name,
    validate_federation_role_arn,
)

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/example-grant/"
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


def _identity() -> FederationIdentity:
    return FederationIdentity(
        credentials=AwsCredentials(
            access_key_id="ASIAFED",
            secret_access_key="fed-secret",
            session_token="fed-token",
            expiration=NOW + timedelta(hours=1),
        ),
        session_name=CALLER_ROLE,
        project="example",
    )


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError(
        error_response={"Error": {"Code": code, "Message": code}},
        operation_name=operation,
    )


class TestValidateFederationRoleArn:
    def test_accepts_role_under_prefix_in_allowed_account(self):
        validate_federation_role_arn(ROLE_ARN, [ACCOUNT], "/portunus-fed/")

    @pytest.mark.parametrize(
        "arn",
        [
            f"arn:aws:iam::{ACCOUNT}:role/example-grant@projects.example",
            f"arn:aws:iam::{ACCOUNT}:role/other/example-grant/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed-x/example-grant/name",
            f"arn:aws:iam::{OTHER_ACCOUNT}:role/portunus-fed/example-grant/name",
            f"arn:aws:iam::{ACCOUNT}:user/portunus-fed/example-grant/name",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/portunus-fed/name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed//name",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/example-grant/name\n",
            f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/example-grant/na me",
            "not-an-arn",
            "",
        ],
    )
    def test_rejects_arns_outside_the_allowed_set(self, arn: str):
        with pytest.raises(AuthenticationError):
            validate_federation_role_arn(arn, [ACCOUNT], "/portunus-fed/")

    def test_empty_allowlist_disables_minting(self):
        with pytest.raises(AuthenticationError, match="disabled"):
            validate_federation_role_arn(ROLE_ARN, [], "/portunus-fed/")

    def test_path_prefix_is_configurable(self):
        arn = f"arn:aws:iam::{ACCOUNT}:role/custom-fed/grant/name"
        validate_federation_role_arn(arn, [ACCOUNT], "/custom-fed/")
        with pytest.raises(AuthenticationError, match="role path"):
            validate_federation_role_arn(ROLE_ARN, [ACCOUNT], "/custom-fed/")


class TestCallerIdentityFields:
    def test_role_name_comes_from_assumed_role_principal(self):
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
        "Expiration": NOW + timedelta(hours=1),
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
    async def test_non_assumed_role_caller_is_rejected_before_sts(self):
        session, clients = _sts_session(assume_role=ASSUME_ROLE_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(CredentialsError):
            await service.assume_federation_role(
                CALLER_CREDENTIALS, PrincipalInfo(principal=None), ROLE_ARN
            )

        assert clients == []

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
            project_tag_key="example:project",
        )
        service = StsFederationService(session, federation_config)

        proof = await service.web_identity_token(
            _identity(), "https://api.example.com", 3600
        )

        (client,) = clients
        assert client.create_kwargs["aws_access_key_id"] == "ASIAFED"
        assert client.create_kwargs["aws_session_token"] == "fed-token"
        assert client.create_kwargs["endpoint_url"] == STS_ENDPOINT
        client.get_web_identity_token.assert_awaited_once_with(
            Audience=["https://api.example.com"],
            SigningAlgorithm="RS256",
            DurationSeconds=IDENTITY_TOKEN_SECONDS,
            Tags=[
                {"Key": "example:user", "Value": CALLER_ROLE},
                {"Key": "example:project", "Value": "example"},
            ],
        )
        assert proof == WebIdentityToken(
            token="header.payload.signature", expires_at=NOW + timedelta(minutes=15)
        )

    @pytest.mark.asyncio
    async def test_secret_duration_caps_identity_token(self):
        session, clients = _sts_session(get_web_identity_token=WEB_IDENTITY_RESPONSE)
        service = StsFederationService(session, FEDERATION_CONFIG)

        await service.web_identity_token(_identity(), "https://api.example.com", 300)

        (client,) = clients
        call = client.get_web_identity_token.await_args_list[0]
        assert call.kwargs["DurationSeconds"] == 300

    @pytest.mark.asyncio
    async def test_web_identity_token_failure_raises_authentication_error(self):
        session, _ = _sts_session(
            get_web_identity_token=_client_error("AccessDenied", "GetWebIdentityToken")
        )
        service = StsFederationService(session, FEDERATION_CONFIG)

        with pytest.raises(AuthenticationError, match="identity token"):
            await service.web_identity_token(
                _identity(), "https://api.example.com", 3600
            )

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


def _exchange(
    handler: Callable[[httpx.Request], httpx.Response] | Exception,
) -> tuple[AnthropicTokenExchange, list[httpx.Request]]:
    """An exchange adapter over an in-memory transport; returns (adapter, requests)."""
    requests: list[httpx.Request] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if isinstance(handler, Exception):
            raise handler
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))
    return AnthropicTokenExchange(http_client=client), requests


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
    async def test_transport_failure_raises(self):
        adapter, _ = _exchange(httpx.ConnectError("connection refused"))

        with pytest.raises(AuthenticationError, match="failed"):
            await adapter.exchange("header.payload.signature", _secret())


class TestTokenMintService:
    def _service(self) -> tuple[TokenMintService, MagicMock, MagicMock]:
        sts = MagicMock()
        sts.assume_federation_role = AsyncMock(return_value=_identity())
        tokens = iter(["jwt-1", "jwt-2", "jwt-3"])
        sts.web_identity_token = AsyncMock(
            side_effect=lambda *args, **kwargs: WebIdentityToken(
                token=next(tokens), expires_at=NOW + timedelta(minutes=15)
            )
        )
        anthropic = MagicMock()
        anthropic.exchange = AsyncMock(
            side_effect=lambda assertion, secret: MintedToken(
                token=f"token-for-{assertion}", expires_at=NOW + timedelta(hours=1)
            )
        )
        return (
            TokenMintService(
                sts=sts, anthropic=anthropic, federation_config=FEDERATION_CONFIG
            ),
            sts,
            anthropic,
        )

    @pytest.mark.asyncio
    async def test_mint_sequences_proof_and_exchange(self):
        service, sts, anthropic = self._service()
        secret = _secret(token_duration_seconds=1200)

        minted = await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_awaited_once_with(
            CALLER_CREDENTIALS, CALLER, ROLE_ARN
        )
        sts.web_identity_token.assert_awaited_once_with(
            _identity(), "https://api.anthropic.com", 1200
        )
        anthropic.exchange.assert_awaited_once_with("jwt-1", secret)
        assert minted.token == "token-for-jwt-1"

    @pytest.mark.asyncio
    async def test_each_mint_uses_a_fresh_identity_token(self):
        service, sts, anthropic = self._service()

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
        service, sts, anthropic = self._service()
        secret = _secret(
            federation_role_arn=(
                f"arn:aws:iam::{OTHER_ACCOUNT}:role/portunus-fed/grant/name"
            )
        )

        with pytest.raises(AuthenticationError, match="allowed account"):
            await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_not_awaited()
        sts.web_identity_token.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unknown_mint_type_has_no_exchange(self):
        class OtherSecret(MintSecretBase):
            type: Literal["other"] = "other"

        service, sts, anthropic = self._service()
        secret = OtherSecret(host="api.example.com", federation_role_arn=ROLE_ARN)

        with pytest.raises(AuthenticationError, match="OtherSecret"):
            await service.mint(CALLER_CREDENTIALS, CALLER, secret)

        sts.assume_federation_role.assert_not_awaited()
        anthropic.exchange.assert_not_awaited()
