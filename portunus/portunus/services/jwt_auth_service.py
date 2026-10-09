"""On-behalf-of access: verify an auth-relay access token and serve this proxy's key.

The auth relay mints short-lived ES256 ``at+jwt`` tokens (RFC 8693 token
exchange) for an allowlisted app acting for a signed-in user. The caller holds
no AWS credentials, so authority comes from the token (who, through which app,
for which project) plus this proxy's policy, and the upstream key is the one the
proxy is configured with, read with Portunus's own credentials.

Payload authentication is unchanged; ``looks_like_jwt`` decides which path a
bearer takes.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Optional

import httpx
import jwt

from portunus.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialsError,
    UpstreamServiceError,
)
from portunus.models import AuthResult, MintSecretBase, PrincipalInfo
from portunus.services.secret_validation_service import SecretValidationService

logger = logging.getLogger("api.access")

ALGORITHMS = ("ES256",)
# RFC 9068 allows the media-type form too; typ compares case-insensitively.
ACCESS_TOKEN_TYPS = ("at+jwt", "application/at+jwt")
_REQUIRED_CLAIMS = ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"]


@dataclass(frozen=True)
class JwtSettings:
    """Which tokens this proxy accepts, and the key it serves for them.

    Attributes:
        issuer: Expected ``iss`` (the auth relay's base URL).
        audience: Expected ``aud``.
        jwks_url: The relay's ``/.well-known/jwks.json``.
        allowed_clients: Apps (``client_id``) this proxy serves. Must be explicit.
        allowed_projects: Projects this proxy serves; ``*`` for any.
        upstream_secret_arn: The provider key served to JWT callers
            (``upstream_mode="secret"``).
        upstream_mode: ``"secret"`` injects the stored key; ``"envoy_sigv4"``
            injects nothing and leaves the upstream credential to Envoy's
            ``aws_request_signing`` filter (AWS upstreams such as Bedrock).
        max_lifetime_seconds: Longest ``exp - iat`` accepted.
        leeway_seconds: Clock skew tolerated on ``exp`` / ``nbf``.
        jwks_cache_seconds: How long fetched keys are trusted.
        jwks_min_refresh_seconds: Least interval between refetches an unknown
            ``kid`` may force, and between retries after a failed fetch, so random
            kids or a relay outage cannot hammer the relay.
        jwks_max_stale_seconds: How long keys stay usable past their cache life
            while the relay cannot be reached.
        secret_cache_seconds: How long the provider key is reused in process.
        allow_http_jwks: Permit a plain-HTTP JWKS URL (ranges only).
        models: The models this proxy serves, each ``{"id", "display_name",
            "projects"}``; ``projects`` is a list of project names or ``["*"]``.
            Reported by the entitlements endpoint, filtered by the token's
            project. Empty means the proxy reports no models.
    """

    issuer: str
    audience: str
    jwks_url: str
    allowed_clients: frozenset[str]
    allowed_projects: frozenset[str]
    upstream_secret_arn: str
    upstream_mode: str = "secret"
    max_lifetime_seconds: int = 900
    leeway_seconds: int = 30
    jwks_cache_seconds: int = 300
    jwks_min_refresh_seconds: int = 30
    jwks_max_stale_seconds: int = 3600
    secret_cache_seconds: int = 300
    allow_http_jwks: bool = False
    models: tuple[dict, ...] = ()

    def __post_init__(self) -> None:
        if not self.allowed_clients:
            raise ValueError("JWT_ALLOWED_CLIENTS must name at least one client")
        if not self.allowed_projects:
            raise ValueError("JWT_ALLOWED_PROJECTS must be set ('*' for any)")
        if self.upstream_mode not in ("secret", "envoy_sigv4"):
            raise ValueError("JWT_UPSTREAM_MODE must be 'secret' or 'envoy_sigv4'")
        needs_secret = self.upstream_mode == "secret"
        if not (self.issuer and self.audience and self.jwks_url) or (
            needs_secret and not self.upstream_secret_arn
        ):
            raise ValueError(
                "JWT issuer, audience and JWKS URL are required, plus the upstream "
                "secret unless JWT_UPSTREAM_MODE=envoy_sigv4"
            )
        if not self.jwks_url.startswith("https://") and not self.allow_http_jwks:
            raise ValueError(
                "JWT_JWKS_URL must be https (JWT_JWKS_ALLOW_HTTP for ranges)"
            )
        for model in self.models:
            if not isinstance(model.get("id"), str) or not isinstance(
                model.get("display_name"), str
            ):
                raise ValueError("JWT_MODELS entries need string id and display_name")
            if not isinstance(model.get("projects", ["*"]), list):
                raise ValueError("JWT_MODELS projects must be a list")

    def models_for(self, project: str) -> list[dict]:
        """The models ``project`` may use here, as ``{"id", "display_name"}``."""
        return [
            {"id": m["id"], "display_name": m["display_name"]}
            for m in self.models
            if "*" in m.get("projects", ["*"]) or project in m.get("projects", ["*"])
        ]


def looks_like_jwt(value: str) -> bool:
    """True when ``value`` is a compact JWS whose header names an algorithm.

    Payloads are base64 JSON without dots, so this never misroutes one.
    """
    parts = value.split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return False
    try:
        header = json.loads(
            base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        )
    except (binascii.Error, ValueError):
        return False
    return isinstance(header, dict) and "alg" in header


def _enforce_model_scope(models: Optional[list], request_body: Optional[bytes]) -> None:
    """A token scoped to ``models`` may only name one of them in the request body."""
    if models is None:
        return
    if request_body is None:
        raise AuthenticationError(
            "Access token is scoped to specific models but the request body "
            "was not available to check"
        )
    try:
        requested = json.loads(request_body).get("model")
    except (ValueError, AttributeError):
        requested = None
    if not isinstance(requested, str) or not requested:
        raise AuthenticationError(
            "Access token is scoped to specific models; the request names none"
        )
    if requested not in models:
        raise AuthenticationError(f"Access token is not scoped to model {requested}")


def _numeric_date(claims: dict, name: str) -> float:
    value = claims.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise CredentialsError("Access token times are malformed")
    return float(value)


class _Jwks:
    """The relay's signing keys.

    Cached for ``jwks_cache_seconds``; an unknown ``kid`` forces a refetch at most
    once per ``jwks_min_refresh_seconds``. Concurrent refreshes share one fetch. A
    failed fetch is not retried for ``jwks_min_refresh_seconds``, and keys already
    held keep being served for up to ``jwks_max_stale_seconds`` past their cache
    life, so a relay outage neither fans out into a fetch per request nor turns
    every request into a 503.
    """

    def __init__(
        self,
        fetch: Callable[[], Awaitable[dict]],
        settings: JwtSettings,
        clock: Callable[[], float],
    ):
        self._fetch = fetch
        self._settings = settings
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._loaded_at = float("-inf")
        self._forced_at = float("-inf")
        self._failed_at = float("-inf")
        self._attempts = 0  # bumped by every fetch attempt, for single flight
        self._lock = asyncio.Lock()

    async def key(self, kid: Optional[str]) -> Any:
        now = self._clock()
        if now - self._loaded_at > self._settings.jwks_cache_seconds:
            await self._refresh(now)
        elif (
            kid not in self._keys
            and now - self._forced_at >= self._settings.jwks_min_refresh_seconds
        ):
            self._forced_at = now
            await self._refresh(now)
        if now - self._loaded_at > self._settings.jwks_cache_seconds + (
            self._settings.jwks_max_stale_seconds
        ):
            raise UpstreamServiceError("Token issuer keys unavailable")
        if kid not in self._keys:
            raise CredentialsError("Access token signed with an unknown key")
        return self._keys[kid]

    async def _refresh(self, requested_at: float) -> None:
        seen = self._attempts
        async with self._lock:
            if self._attempts != seen:
                return  # another request fetched while this one waited
            if requested_at - self._failed_at < self._settings.jwks_min_refresh_seconds:
                return  # the relay just failed; serve what is held, if anything
            try:
                document = await self._fetch()
            except Exception as e:
                self._failed_at = requested_at
                logger.warning("JWKS fetch failed: %s", type(e).__name__)
                return
            finally:
                # Counted once the attempt ends, so every request already
                # waiting on the lock sees it and skips its own fetch.
                self._attempts += 1
            keys = {}
            for entry in document.get("keys", []):
                if (
                    entry.get("kty") == "EC"
                    and entry.get("crv") == "P-256"
                    and entry.get("kid")
                ):
                    keys[entry["kid"]] = jwt.PyJWK(entry, algorithm="ES256").key
            self._keys, self._loaded_at = keys, requested_at


class JwtAuthService:
    """Authenticates on-behalf-of access tokens for one proxy.

    Args:
        settings: Accepted tokens and the key to serve.
        fetch_jwks: Returns the relay's JWKS document; defaults to an HTTP GET.
        fetch_service_secret: Reads a secret with Portunus's own credentials.
        validation_service: Parses the secret and enforces its host restriction.
        clock: Seconds since the epoch.
    """

    def __init__(
        self,
        settings: JwtSettings,
        *,
        fetch_service_secret: Callable[[str], Awaitable[str]],
        fetch_jwks: Optional[Callable[[], Awaitable[dict]]] = None,
        validation_service: Optional[SecretValidationService] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._jwks = _Jwks(fetch_jwks or self._http_jwks, settings, clock)
        self._fetch_secret = fetch_service_secret
        self._validation = validation_service or SecretValidationService()
        self._secret_cache: dict[Optional[str], tuple[float, str]] = {}
        self._secret_lock = asyncio.Lock()

    async def _http_jwks(self) -> dict:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(self._settings.jwks_url)
            response.raise_for_status()
            return response.json()

    async def authenticate(
        self,
        token: str,
        request_id: str,
        target_host: Optional[str],
        request_body: Optional[bytes] = None,
    ) -> tuple[AuthResult, Optional[str]]:
        """Verify ``token`` and return the upstream credential and its secret ARN.

        ``request_body`` is needed only for tokens scoped to particular
        ``models``: the model is named in the JSON body, so Envoy must send it
        (``EXT_AUTHZ_REQUEST_BODY_BYTES``), and a scoped token with no body to
        check is refused.

        Raises:
            CredentialsError: The token is not a valid access token (401).
            AuthenticationError: Valid, but this proxy does not serve its client
                or project, or the key is not for ``target_host`` (403).
            UpstreamServiceError: The relay's keys could not be fetched (503).
            ConfigurationError: The configured secret cannot serve JWT callers.
        """
        claims = await self._authorise(token)
        client_id, project = claims["client_id"], claims["project"]
        _enforce_model_scope(claims.get("models"), request_body)
        # Empty key: nothing to inject; Envoy signs the upstream request.
        api_key = (
            ""
            if self._settings.upstream_mode == "envoy_sigv4"
            else await self._upstream_key(target_host)
        )
        principal = PrincipalInfo(
            arn=None,
            account_id=None,
            principal=claims.get("email"),
            session_name=None,
            project=project,
            auth_method="jwt",
            subject=claims["sub"],
            actor=client_id,
            teams=list(claims.get("teams", [])),
            token_id=claims["jti"],
        )
        logger.info(
            "On-behalf-of request authorised "
            "(request_id=%s client=%s project=%s jti=%s)",
            request_id,
            client_id,
            project,
            claims["jti"],
        )
        return AuthResult(api_key=api_key, principal_info=principal), (
            self._settings.upstream_secret_arn or None
        )

    async def entitlements(
        self, token: str, request_id: str, target_host: Optional[str]
    ) -> dict:
        """What the token's subject may use on this proxy; no key is touched.

        Raises as :meth:`authenticate` does, minus the secret read.
        """
        claims = await self._authorise(token)
        logger.info(
            "Entitlements served (request_id=%s client=%s project=%s jti=%s)",
            request_id,
            claims["client_id"],
            claims["project"],
            claims["jti"],
        )
        return {
            "subject": claims["sub"],
            "email": claims.get("email"),
            "teams": list(claims.get("teams", [])),
            "project": claims["project"],
            "actor": claims["client_id"],
            "provider_host": target_host,
            "models": [
                m
                for m in self._settings.models_for(claims["project"])
                if claims.get("models") is None or m["id"] in claims["models"]
            ],
            "scoped_models": claims.get("models"),
        }

    async def _authorise(self, token: str) -> dict:
        """Verify the token and apply this proxy's client and project policy."""
        claims = await self._verify(token)
        if claims["client_id"] not in self._settings.allowed_clients:
            raise AuthenticationError("This proxy does not serve that application")
        if not (
            "*" in self._settings.allowed_projects
            or claims["project"] in self._settings.allowed_projects
        ):
            raise AuthenticationError("This proxy does not serve that project")
        return claims

    async def _verify(self, token: str) -> dict:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as e:
            raise CredentialsError("Malformed access token") from e
        typ = header.get("typ")
        if (
            not isinstance(typ, str)
            or typ.lower() not in ACCESS_TOKEN_TYPS
            or header.get("alg") not in ALGORITHMS
        ):
            raise CredentialsError("Not an access token this proxy accepts")
        key = await self._jwks.key(header.get("kid"))
        try:
            # Times are checked below against the injected clock, not PyJWT's.
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(ALGORITHMS),
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                options={
                    "require": _REQUIRED_CLAIMS,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidTokenError as e:
            raise CredentialsError(f"Invalid access token ({type(e).__name__})") from e
        self._check_times(claims)
        for name in ("sub", "jti", "client_id", "project"):
            if not isinstance(claims.get(name), str) or not claims[name]:
                raise CredentialsError(f"Access token claim {name} is malformed")
        if not isinstance(claims.get("email", ""), str):
            raise CredentialsError("Access token claim email is malformed")
        teams = claims.get("teams", [])
        if not isinstance(teams, list) or not all(isinstance(t, str) for t in teams):
            raise CredentialsError("Access token claim teams is malformed")
        actor = claims.get("act")
        if not isinstance(actor, dict) or actor.get("sub") != claims["client_id"]:
            raise CredentialsError("Access token does not name its acting application")
        models = claims.get("models")
        if models is not None and (
            not isinstance(models, list)
            or not models
            or not all(isinstance(m, str) and m for m in models)
        ):
            raise CredentialsError("Access token claim models is malformed")
        return claims

    def _check_times(self, claims: dict) -> None:
        iat, nbf, exp = (_numeric_date(claims, name) for name in ("iat", "nbf", "exp"))
        now, leeway = self._clock(), self._settings.leeway_seconds
        if exp <= now - leeway:
            raise CredentialsError("Access token has expired")
        if nbf > now + leeway or iat > now + leeway:
            raise CredentialsError("Access token is not yet valid")
        if exp - iat > self._settings.max_lifetime_seconds:
            raise CredentialsError("Access token lifetime exceeds this proxy's limit")

    async def _upstream_key(self, target_host: Optional[str]) -> str:
        now = self._clock()
        cached = self._secret_cache.get(target_host)
        if cached and cached[0] > now:
            return cached[1]
        async with self._secret_lock:
            cached = self._secret_cache.get(target_host)
            if cached and cached[0] > now:
                return cached[1]
            raw = await self._fetch_secret(self._settings.upstream_secret_arn)
            secret = self._validation.validate_secret(raw, target_host)
            if isinstance(secret, MintSecretBase):
                raise ConfigurationError("JWT callers can only be served a stored key")
            self._secret_cache[target_host] = (
                now + self._settings.secret_cache_seconds,
                secret.api_key,
            )
            return secret.api_key
