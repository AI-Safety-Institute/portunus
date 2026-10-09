"""On-behalf-of access tokens: verification, policy and the proxy's own key.

The auth relay mints short-lived ES256 ``at+jwt`` tokens for an allowlisted app
acting for a signed-in user. Portunus verifies them against the relay's JWKS,
applies this proxy's client and project policy, and serves the provider key it
fetches with its own credentials.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
    UpstreamServiceError,
)
from portunus.services.jwt_auth_service import (
    JwtAuthService,
    JwtSettings,
    looks_like_jwt,
)
from portunus.services.secret_validation_service import SecretValidationService

ISSUER = "https://auth.example.com"
SECRET_ARN = (
    "arn:aws:secretsmanager:eu-west-2:111111111111:secret:portal/anthropic-AbCdEf"
)
TARGET = "mock-provider"
NOW = 1_800_000_000


def _key() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    return key, jwk


class _Relay:
    """The auth relay's signing key and JWKS endpoint."""

    def __init__(self) -> None:
        self.key, jwk = _key()
        self.kid = "relay-key-1"
        self.jwks = {"keys": [{**jwk, "kid": self.kid, "alg": "ES256", "use": "sig"}]}
        self.fetches = 0
        self.fail = False

    async def fetch(self) -> dict:
        self.fetches += 1
        await asyncio.sleep(0.01)  # a real round trip, so concurrent callers overlap
        if self.fail:
            raise OSError("relay unreachable")
        return self.jwks

    def mint(self, *, key=None, header: Optional[dict] = None, **overrides: Any) -> str:
        claims = {
            "iss": ISSUER,
            "aud": "portunus",
            "sub": "U0123456789",
            "email": "test@example.com",
            "teams": ["core-tech"],
            "project": "harness-project",
            "client_id": "demo-app",
            "act": {"sub": "demo-app"},
            "iat": NOW,
            "nbf": NOW,
            "exp": NOW + 600,
            "jti": "4b1d0c0e",
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        headers = {"kid": self.kid, "typ": "at+jwt", **(header or {})}
        return jwt.encode(claims, key or self.key, algorithm="ES256", headers=headers)


class _Secrets:
    """Portunus's own Secrets Manager reads, counted."""

    def __init__(self, value: dict) -> None:
        self.value = value
        self.reads: list[str] = []

    async def fetch(self, secret_arn: str) -> str:
        self.reads.append(secret_arn)
        return json.dumps(self.value)


def _service(
    relay: _Relay,
    secrets: Optional[_Secrets] = None,
    clock=lambda: NOW,
    **settings: Any,
):
    secrets = secrets or _Secrets({"secret": "sk-upstream", "host": TARGET})
    defaults: dict[str, Any] = dict(
        issuer=ISSUER,
        audience="portunus",
        jwks_url=f"{ISSUER}/.well-known/jwks.json",
        allowed_clients=frozenset({"demo-app"}),
        allowed_projects=frozenset({"*"}),
        upstream_secret_arn=SECRET_ARN,
    )
    defaults.update(settings)
    service = JwtAuthService(
        JwtSettings(**defaults),
        fetch_jwks=relay.fetch,
        fetch_service_secret=secrets.fetch,
        validation_service=SecretValidationService(),
        clock=clock,
    )
    return service, secrets


@pytest.fixture
def relay() -> _Relay:
    return _Relay()


class TestShape:
    def test_jwts_are_told_apart_from_payloads(self, relay):
        assert looks_like_jwt(relay.mint())
        assert not looks_like_jwt("eyJjcmVkZW50aWFscyI6IHt9fQ==")  # a base64 payload
        assert not looks_like_jwt("a.b.c")
        assert not looks_like_jwt("")


@pytest.mark.asyncio
class TestAccepted:
    async def test_attributes_the_user_app_and_project_and_serves_the_proxy_key(
        self, relay
    ):
        service, secrets = _service(relay)

        result, secret_arn = await service.authenticate(relay.mint(), "req-1", TARGET)

        assert result.api_key == "sk-upstream"
        assert secret_arn == SECRET_ARN
        assert secrets.reads == [SECRET_ARN]
        info = result.principal_info
        assert info.auth_method == "jwt"
        assert info.subject == "U0123456789"
        assert info.principal == "test@example.com"
        assert info.actor == "demo-app"
        assert info.teams == ["core-tech"]
        assert info.project == "harness-project"
        assert info.token_id == "4b1d0c0e"
        assert info.arn is None and info.account_id is None

    async def test_the_proxy_key_is_read_once_and_reused(self, relay):
        service, secrets = _service(relay)
        await service.authenticate(relay.mint(), "req-1", TARGET)
        await service.authenticate(relay.mint(sub="U999"), "req-2", TARGET)
        assert secrets.reads == [SECRET_ARN]

    async def test_clock_skew_within_leeway_is_tolerated(self, relay):
        service, _ = _service(relay, clock=lambda: NOW - 20)
        await service.authenticate(relay.mint(), "req-1", TARGET)


@pytest.mark.asyncio
class TestRejectedTokens:
    @pytest.mark.parametrize(
        "overrides",
        [
            {
                "exp": NOW - 31,
                "iat": NOW - 600,
                "nbf": NOW - 600,
            },  # expired past leeway
            {"nbf": NOW + 31, "iat": NOW + 31, "exp": NOW + 600},  # not yet valid
            {"aud": "openai-proxy"},
            {"iss": "https://evil.example.com"},
            {"exp": NOW + 3600},  # longer than the lifetime cap
            {"jti": None},
            {"sub": None},
            {"act": {"sub": "rogue-app"}},  # actor must be the client
            {"act": None},
        ],
    )
    async def test_invalid_claims_are_401(self, relay, overrides):
        service, secrets = _service(relay)
        with pytest.raises(CredentialsError):
            await service.authenticate(relay.mint(**overrides), "req-1", TARGET)
        assert secrets.reads == []

    async def test_a_different_signing_key_is_401(self, relay):
        service, _ = _service(relay)
        forged = relay.mint(key=_key()[0])
        with pytest.raises(CredentialsError):
            await service.authenticate(forged, "req-1", TARGET)

    async def test_a_token_that_is_not_an_access_token_is_401(self, relay):
        service, _ = _service(relay)
        with pytest.raises(CredentialsError):
            await service.authenticate(
                relay.mint(header={"typ": "JWT"}), "req-1", TARGET
            )

    async def test_only_es256_is_accepted(self, relay):
        service, _ = _service(relay)
        claims = jwt.decode(relay.mint(), options={"verify_signature": False})
        hs256 = jwt.encode(
            claims,
            "a-shared-secret-at-least-32-bytes-long",
            algorithm="HS256",
            headers={"kid": relay.kid, "typ": "at+jwt"},
        )
        unsigned = jwt.encode(
            claims, None, algorithm="none", headers={"kid": relay.kid, "typ": "at+jwt"}
        )
        for token in (hs256, unsigned):
            with pytest.raises(CredentialsError):
                await service.authenticate(token, "req-1", TARGET)


@pytest.mark.asyncio
class TestPolicy:
    async def test_an_app_this_proxy_does_not_serve_is_403(self, relay):
        service, secrets = _service(relay, allowed_clients=frozenset({"hub"}))
        with pytest.raises(AuthenticationError):
            await service.authenticate(relay.mint(), "req-1", TARGET)
        assert secrets.reads == []

    async def test_a_project_this_proxy_does_not_serve_is_403(self, relay):
        service, _ = _service(relay, allowed_projects=frozenset({"default"}))
        with pytest.raises(AuthenticationError):
            await service.authenticate(relay.mint(), "req-1", TARGET)

    async def test_the_secrets_host_restriction_still_applies(self, relay):
        service, _ = _service(relay)
        with pytest.raises(AuthenticationError):
            await service.authenticate(relay.mint(), "req-1", "api.openai.com")

    async def test_mint_secrets_are_not_served_to_jwt_callers_yet(self, relay):
        secrets = _Secrets(
            {
                "type": "anthropic_wif",
                "host": TARGET,
                "federation_role_arn": "arn:aws:iam::111111111111:role/portunus-fed/x",
                "federation_rule_id": "r",
                "organization_id": "o",
                "service_account_id": "s",
                "workspace_id": "w",
            }
        )
        service, _ = _service(relay, secrets)
        with pytest.raises(ConfigurationError):
            await service.authenticate(relay.mint(), "req-1", TARGET)


@pytest.mark.asyncio
class TestJwks:
    async def test_keys_are_cached(self, relay):
        service, _ = _service(relay)
        for i in range(3):
            await service.authenticate(relay.mint(jti=f"j{i}"), f"req-{i}", TARGET)
        assert relay.fetches == 1

    async def test_an_unknown_kid_refetches_once_then_is_rate_limited(self, relay):
        service, _ = _service(relay)
        await service.authenticate(relay.mint(), "req-0", TARGET)
        for i in range(5):
            with pytest.raises(CredentialsError):
                await service.authenticate(
                    relay.mint(header={"kid": f"rotated-{i}"}), "req", TARGET
                )
        assert relay.fetches == 2

    async def test_a_rotated_key_is_picked_up(self, relay):
        clock = [NOW]
        service, _ = _service(relay, clock=lambda: clock[0])
        await service.authenticate(relay.mint(), "req-0", TARGET)
        relay.key, jwk = _key()
        relay.kid = "relay-key-2"
        relay.jwks = {"keys": [{**jwk, "kid": relay.kid, "alg": "ES256", "use": "sig"}]}
        await service.authenticate(relay.mint(), "req-1", TARGET)
        assert relay.fetches == 2

    async def test_an_unreachable_relay_is_503(self, relay):
        relay.fail = True
        service, _ = _service(relay)
        with pytest.raises(UpstreamServiceError):
            await service.authenticate(relay.mint(), "req-1", TARGET)


def test_settings_require_an_explicit_client_allowlist():
    with pytest.raises(ValueError):
        JwtSettings(
            issuer=ISSUER,
            audience="portunus",
            jwks_url="https://x",
            allowed_clients=frozenset(),
            allowed_projects=frozenset({"*"}),
            upstream_secret_arn=SECRET_ARN,
        )


@pytest.fixture
def fresh_config():
    from portunus.config import get_config

    get_config.cache_clear()
    yield
    get_config.cache_clear()


@pytest.mark.usefixtures("fresh_config")
def test_jwt_auth_is_off_unless_an_issuer_is_configured(monkeypatch):
    from portunus.config import get_config

    monkeypatch.delenv("JWT_ISSUER", raising=False)
    assert get_config().jwt.settings() is None


@pytest.mark.usefixtures("fresh_config")
def test_jwt_settings_come_from_the_environment(monkeypatch):
    from portunus.config import get_config

    monkeypatch.setenv("JWT_ISSUER", ISSUER)
    monkeypatch.setenv("JWT_ALLOWED_CLIENTS", "demo-app, hub")
    monkeypatch.setenv("JWT_ALLOWED_PROJECTS", "default,harness-project")
    monkeypatch.setenv("JWT_UPSTREAM_SECRET_ARN", SECRET_ARN)
    settings = get_config().jwt.settings()
    assert settings.issuer == ISSUER
    assert settings.audience == "portunus"
    assert settings.jwks_url == f"{ISSUER}/.well-known/jwks.json"
    assert settings.allowed_clients == frozenset({"demo-app", "hub"})
    assert settings.allowed_projects == frozenset({"default", "harness-project"})
    assert settings.upstream_secret_arn == SECRET_ARN


@pytest.mark.usefixtures("fresh_config")
def test_an_issuer_without_a_client_allowlist_fails_at_startup(monkeypatch):
    from portunus.config import get_config

    monkeypatch.setenv("JWT_ISSUER", ISSUER)
    monkeypatch.setenv("JWT_UPSTREAM_SECRET_ARN", SECRET_ARN)
    monkeypatch.delenv("JWT_ALLOWED_CLIENTS", raising=False)
    with pytest.raises(ValueError):
        get_config().jwt.settings()


@pytest.mark.asyncio
class TestJwksUnderLoadAndOutage:
    async def test_concurrent_requests_after_expiry_share_one_fetch(self, relay):
        clock = [NOW]
        service, _ = _service(relay, clock=lambda: clock[0])
        await service.authenticate(relay.mint(), "req-0", TARGET)
        clock[0] += 301
        tokens = [
            relay.mint(jti=f"j{i}", iat=clock[0], nbf=clock[0], exp=clock[0] + 600)
            for i in range(20)
        ]
        await asyncio.gather(*(service.authenticate(t, "r", TARGET) for t in tokens))
        assert relay.fetches == 2

    async def test_a_relay_outage_serves_the_keys_already_held(self, relay):
        clock = [NOW]
        service, _ = _service(relay, clock=lambda: clock[0])
        await service.authenticate(relay.mint(), "req-0", TARGET)
        relay.fail = True
        clock[0] += 301
        for i in range(5):
            token = relay.mint(
                jti=f"j{i}", iat=clock[0], nbf=clock[0], exp=clock[0] + 600
            )
            await service.authenticate(token, "r", TARGET)
        assert relay.fetches == 2  # one failed refresh, then the failure is remembered

    async def test_keys_stop_being_served_once_too_stale(self, relay):
        clock = [NOW]
        service, _ = _service(relay, clock=lambda: clock[0])
        await service.authenticate(relay.mint(), "req-0", TARGET)
        relay.fail = True
        clock[0] += 3601 + 300
        token = relay.mint(iat=clock[0], nbf=clock[0], exp=clock[0] + 600)
        with pytest.raises(UpstreamServiceError):
            await service.authenticate(token, "r", TARGET)

    async def test_a_cold_start_outage_does_not_fetch_per_request(self, relay):
        relay.fail = True
        service, _ = _service(relay)
        for _ in range(5):
            with pytest.raises(UpstreamServiceError):
                await service.authenticate(relay.mint(), "r", TARGET)
        assert relay.fetches == 1


@pytest.mark.asyncio
class TestClaimTypes:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"client_id": ["demo-app"], "act": {"sub": ["demo-app"]}},
            {"project": ["harness-project"]},
            {"sub": 123},
            {"jti": {"x": 1}},
            {"email": ["a@example.com"]},
            {"teams": "core-tech"},
            {"teams": ["core-tech", 7]},
        ],
    )
    async def test_wrongly_typed_claims_are_401_not_500(self, relay, overrides):
        service, secrets = _service(relay)
        with pytest.raises(CredentialsError):
            await service.authenticate(relay.mint(**overrides), "req-1", TARGET)
        assert secrets.reads == []

    @pytest.mark.parametrize("typ", ["application/at+jwt", "AT+JWT"])
    async def test_rfc_9068_typ_spellings_are_accepted(self, relay, typ):
        service, _ = _service(relay)
        await service.authenticate(relay.mint(header={"typ": typ}), "req-1", TARGET)


def test_jwks_must_be_fetched_over_https_unless_allowed():
    base = dict(
        issuer=ISSUER,
        audience="portunus",
        allowed_clients=frozenset({"demo-app"}),
        allowed_projects=frozenset({"*"}),
        upstream_secret_arn=SECRET_ARN,
    )
    with pytest.raises(ValueError):
        JwtSettings(jwks_url="http://auth.range:8000/.well-known/jwks.json", **base)
    JwtSettings(
        jwks_url="http://auth.range:8000/.well-known/jwks.json",
        allow_http_jwks=True,
        **base,
    )


@pytest.mark.asyncio
class TestEntitlements:
    """What a signed-in subject may use on this proxy, from the token and policy."""

    MODELS = (
        {
            "id": "claude-mock-sonnet",
            "display_name": "Claude Sonnet (mock)",
            "projects": ["*"],
        },
        {
            "id": "claude-mock-opus",
            "display_name": "Claude Opus (mock)",
            "projects": ["harness-project"],
        },
    )

    async def test_lists_the_models_the_tokens_project_may_use(self, relay):
        service, secrets = _service(relay, models=self.MODELS)
        body = await service.entitlements(relay.mint(), "req-1", TARGET)
        assert body["subject"] == "U0123456789"
        assert body["project"] == "harness-project"
        assert body["actor"] == "demo-app"
        assert body["provider_host"] == TARGET
        assert [m["id"] for m in body["models"]] == [
            "claude-mock-sonnet",
            "claude-mock-opus",
        ]
        assert secrets.reads == []  # no provider key is touched

    async def test_project_restricted_models_are_left_out(self, relay):
        service, _ = _service(relay, models=self.MODELS)
        body = await service.entitlements(
            relay.mint(project="default"), "req-1", TARGET
        )
        assert [m["id"] for m in body["models"]] == ["claude-mock-sonnet"]

    async def test_policy_still_applies(self, relay):
        service, _ = _service(
            relay, models=self.MODELS, allowed_clients=frozenset({"hub"})
        )
        with pytest.raises(AuthenticationError):
            await service.entitlements(relay.mint(), "req-1", TARGET)

    async def test_invalid_tokens_are_refused(self, relay):
        service, _ = _service(relay, models=self.MODELS)
        with pytest.raises(CredentialsError):
            await service.entitlements(
                relay.mint(exp=NOW - 600, iat=NOW - 1200, nbf=NOW - 1200),
                "req-1",
                TARGET,
            )


@pytest.mark.usefixtures("fresh_config")
def test_models_policy_comes_from_the_environment(monkeypatch):
    from portunus.config import get_config

    monkeypatch.setenv("JWT_ISSUER", ISSUER)
    monkeypatch.setenv("JWT_ALLOWED_CLIENTS", "demo-app")
    monkeypatch.setenv("JWT_ALLOWED_PROJECTS", "*")
    monkeypatch.setenv("JWT_UPSTREAM_SECRET_ARN", SECRET_ARN)
    monkeypatch.setenv("JWT_MODELS", json.dumps([{"id": "m1", "display_name": "M1"}]))
    settings = get_config().jwt.settings()
    assert settings.models == ({"id": "m1", "display_name": "M1", "projects": ["*"]},)


@pytest.mark.asyncio
class TestEnvoySignedUpstreams:
    """``upstream_mode=envoy_sigv4``: Portunus injects nothing; Envoy signs."""

    async def test_no_key_is_read_and_the_result_carries_none(self, relay):
        service, secrets = _service(
            relay, upstream_mode="envoy_sigv4", upstream_secret_arn=""
        )
        result, secret_arn = await service.authenticate(relay.mint(), "req-1", TARGET)
        assert result.api_key == "" and secret_arn is None
        assert secrets.reads == []
        assert result.principal_info.actor == "demo-app"

    def test_the_mode_must_be_known(self):
        with pytest.raises(ValueError):
            JwtSettings(
                issuer=ISSUER,
                audience="portunus",
                jwks_url="https://x",
                upstream_mode="sigv4",
                allowed_clients=frozenset({"a"}),
                allowed_projects=frozenset({"*"}),
                upstream_secret_arn="",
            )

    def test_secret_mode_still_needs_a_secret(self):
        with pytest.raises(ValueError):
            JwtSettings(
                issuer=ISSUER,
                audience="portunus",
                jwks_url="https://x",
                allowed_clients=frozenset({"a"}),
                allowed_projects=frozenset({"*"}),
                upstream_secret_arn="",
            )


@pytest.mark.usefixtures("fresh_config")
def test_upstream_mode_comes_from_the_environment(monkeypatch):
    from portunus.config import get_config

    monkeypatch.setenv("JWT_ISSUER", ISSUER)
    monkeypatch.setenv("JWT_ALLOWED_CLIENTS", "hub")
    monkeypatch.setenv("JWT_ALLOWED_PROJECTS", "*")
    monkeypatch.setenv("JWT_UPSTREAM_MODE", "envoy_sigv4")
    monkeypatch.delenv("JWT_UPSTREAM_SECRET_ARN", raising=False)
    assert get_config().jwt.settings().upstream_mode == "envoy_sigv4"


@pytest.mark.asyncio
class TestModelScopedTokens:
    """A token with a ``models`` claim may only call those models."""

    MODELS = TestEntitlements.MODELS

    async def test_the_named_model_is_allowed(self, relay):
        service, _ = _service(relay, models=self.MODELS)
        body = json.dumps({"model": "claude-mock-sonnet", "messages": []}).encode()
        result, _ = await service.authenticate(
            relay.mint(models=["claude-mock-sonnet"]),
            "req-1",
            TARGET,
            request_body=body,
        )
        assert result.api_key == "sk-upstream"

    async def test_another_model_is_refused(self, relay):
        service, secrets = _service(relay, models=self.MODELS)
        body = json.dumps({"model": "claude-mock-opus"}).encode()
        with pytest.raises(
            AuthenticationError, match="not scoped to model claude-mock-opus"
        ):
            await service.authenticate(
                relay.mint(models=["claude-mock-sonnet"]),
                "req-1",
                TARGET,
                request_body=body,
            )
        assert secrets.reads == []

    async def test_a_scoped_token_fails_closed_without_a_body_to_check(self, relay):
        service, _ = _service(relay, models=self.MODELS)
        with pytest.raises(AuthenticationError, match="not available"):
            await service.authenticate(
                relay.mint(models=["claude-mock-sonnet"]), "req-1", TARGET
            )
        with pytest.raises(AuthenticationError, match="names none"):
            await service.authenticate(
                relay.mint(models=["claude-mock-sonnet"]),
                "req-1",
                TARGET,
                request_body=b"{}",
            )

    async def test_unscoped_tokens_ignore_the_body(self, relay):
        service, _ = _service(relay, models=self.MODELS)
        await service.authenticate(
            relay.mint(), "req-1", TARGET, request_body=b"not json"
        )

    async def test_entitlements_shrink_to_the_scope(self, relay):
        service, _ = _service(relay, models=self.MODELS)
        body = await service.entitlements(
            relay.mint(models=["claude-mock-opus", "other"]), "req-1", TARGET
        )
        assert [m["id"] for m in body["models"]] == ["claude-mock-opus"]
        assert body["scoped_models"] == ["claude-mock-opus", "other"]

    @pytest.mark.parametrize("models", [[], "claude-mock-sonnet", [1], [""]])
    async def test_malformed_scopes_are_401(self, relay, models):
        service, _ = _service(relay, models=self.MODELS)
        with pytest.raises(CredentialsError):
            await service.authenticate(
                relay.mint(models=models), "req-1", TARGET, request_body=b"{}"
            )
