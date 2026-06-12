"""Tests for live team resolution + stamping (feature-flagged, default off).

Covers:
    * `teams` tag parsing (comma-split, whitespace, empty).
    * The `__unattributed__` sentinel on every failure path.
    * roleArn->teams cache set / get / expiry (separate from the auth cache).
    * ARN -> role-name extraction.
    * Flag-off no-op: no IAM call, principal_info.teams left untouched.
    * A tag-read exception does not break authentication.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio

from portunus.models import (
    TEAMS_DELIMITER,
    UNATTRIBUTED_TEAM,
    AwsCredentials,
    MetadataRecord,
    PrincipalInfo,
)
from portunus.services.arn_service import extract_role_name
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.team_service import (
    TeamService,
    parse_teams_tag,
    teams_to_delimited,
)

ASSUMED_ROLE_ARN = (
    "arn:aws:sts::123456789012:assumed-role/UserProfile_Alice_chembio/session-1"
)
EXPECTED_ROLE_ARN = "arn:aws:iam::123456789012:role/UserProfile_Alice_chembio"


class FakeStateService:
    """Minimal StateService stand-in that returns a (possibly None) redis client."""

    def __init__(self, client):
        self._client = client

    async def acquire_redis_connection(self, max_retries=8):
        return self._client


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
def credentials():
    return AwsCredentials(
        access_key_id="AKIATEST123",
        secret_access_key="secretkey123",
        session_token="sessiontoken123",
    )


# --------------------------------------------------------------------------- #
# Tag parsing
# --------------------------------------------------------------------------- #


class TestParseTeamsTag:
    def test_single_team(self):
        assert parse_teams_tag("chembio") == ["chembio"]

    def test_comma_split(self):
        assert parse_teams_tag("chembio,soe") == ["chembio", "soe"]

    def test_strips_whitespace_and_empties(self):
        assert parse_teams_tag(" chembio , , soe ,") == ["chembio", "soe"]

    def test_none_returns_empty(self):
        assert parse_teams_tag(None) == []

    def test_empty_string_returns_empty(self):
        assert parse_teams_tag("") == []

    def test_only_delimiters_returns_empty(self):
        assert parse_teams_tag(",, ,") == []


class TestTeamsToDelimited:
    def test_joins_with_delimiter(self):
        assert teams_to_delimited(["a", "b"]) == f"a{TEAMS_DELIMITER}b"

    def test_empty_list_is_sentinel(self):
        assert teams_to_delimited([]) == UNATTRIBUTED_TEAM


# --------------------------------------------------------------------------- #
# ARN -> role name
# --------------------------------------------------------------------------- #


class TestExtractRoleName:
    def test_assumed_role(self):
        assert extract_role_name(ASSUMED_ROLE_ARN) == "UserProfile_Alice_chembio"

    def test_non_assumed_role_returns_none(self):
        assert extract_role_name("arn:aws:iam::123456789012:user/bob") is None

    def test_empty_returns_none(self):
        assert extract_role_name("") is None

    def test_garbage_returns_none(self):
        assert extract_role_name("not-an-arn") is None


# --------------------------------------------------------------------------- #
# roleArn -> teams cache (separate namespace from the auth cache)
# --------------------------------------------------------------------------- #


class TestTeamCache:
    @pytest.mark.asyncio
    async def test_set_then_get(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        assert await cache.cache_teams(EXPECTED_ROLE_ARN, "chembio,soe") is True
        assert await cache.get_cached_teams(EXPECTED_ROLE_ARN) == "chembio,soe"

    @pytest.mark.asyncio
    async def test_miss_returns_none(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        assert await cache.get_cached_teams(EXPECTED_ROLE_ARN) is None

    @pytest.mark.asyncio
    async def test_uses_separate_namespace(self, fake_redis):
        """Team keys must not collide with the SHA-256 payload auth keys."""
        cache = CacheService(state_service=FakeStateService(fake_redis))
        await cache.cache_teams(EXPECTED_ROLE_ARN, "chembio")
        keys = await fake_redis.keys("*")
        assert keys == [f"team:{EXPECTED_ROLE_ARN}"]

    @pytest.mark.asyncio
    async def test_expiry(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        await cache.cache_teams(EXPECTED_ROLE_ARN, "chembio", ttl_seconds=100)
        ttl = await fake_redis.ttl(f"team:{EXPECTED_ROLE_ARN}")
        assert 0 < ttl <= 100

    @pytest.mark.asyncio
    async def test_non_positive_ttl_skips(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        assert await cache.cache_teams(EXPECTED_ROLE_ARN, "x", ttl_seconds=0) is False
        assert await cache.get_cached_teams(EXPECTED_ROLE_ARN) is None

    @pytest.mark.asyncio
    async def test_get_no_redis_returns_none(self):
        cache = CacheService(state_service=FakeStateService(None))
        assert await cache.get_cached_teams(EXPECTED_ROLE_ARN) is None


# --------------------------------------------------------------------------- #
# TeamService.resolve_teams
# --------------------------------------------------------------------------- #


def _team_service_with_tags(cache, tags):
    """Build a TeamService whose IAM client returns the given tag list."""
    service = TeamService(cache_service=cache)
    iam_client = AsyncMock()
    iam_client.list_role_tags = AsyncMock(return_value={"Tags": tags})
    iam_client.__aenter__ = AsyncMock(return_value=iam_client)
    iam_client.__aexit__ = AsyncMock(return_value=None)
    service.boto_session = MagicMock()
    service.boto_session.create_client = MagicMock(return_value=iam_client)
    return service, iam_client


class TestResolveTeams:
    @pytest.mark.asyncio
    async def test_resolves_and_caches(self, fake_redis, credentials):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, iam_client = _team_service_with_tags(
            cache, [{"Key": "teams", "Value": "chembio,soe"}]
        )

        result = await service.resolve_teams(credentials, ASSUMED_ROLE_ARN)

        assert result == "chembio,soe"
        # cached under the role ARN for next time
        assert await cache.get_cached_teams(EXPECTED_ROLE_ARN) == "chembio,soe"

    @pytest.mark.asyncio
    async def test_cache_hit_skips_iam(self, fake_redis, credentials):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        await cache.cache_teams(EXPECTED_ROLE_ARN, "chembio")
        service, iam_client = _team_service_with_tags(cache, [])

        result = await service.resolve_teams(credentials, ASSUMED_ROLE_ARN)

        assert result == "chembio"
        iam_client.list_role_tags.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_tag_is_unattributed(self, fake_redis, credentials):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, _ = _team_service_with_tags(
            cache, [{"Key": "owner", "Value": "someone"}]
        )

        result = await service.resolve_teams(credentials, ASSUMED_ROLE_ARN)

        assert result == UNATTRIBUTED_TEAM

    @pytest.mark.asyncio
    async def test_unparseable_arn_is_unattributed(self, fake_redis, credentials):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, iam_client = _team_service_with_tags(cache, [])

        result = await service.resolve_teams(credentials, "arn:aws:iam::1:user/bob")

        assert result == UNATTRIBUTED_TEAM
        iam_client.list_role_tags.assert_not_called()

    @pytest.mark.asyncio
    async def test_iam_exception_is_unattributed(self, fake_redis, credentials):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service = TeamService(cache_service=cache)
        iam_client = AsyncMock()
        iam_client.list_role_tags = AsyncMock(side_effect=Exception("AccessDenied"))
        iam_client.__aenter__ = AsyncMock(return_value=iam_client)
        iam_client.__aexit__ = AsyncMock(return_value=None)
        service.boto_session = MagicMock()
        service.boto_session.create_client = MagicMock(return_value=iam_client)

        result = await service.resolve_teams(credentials, ASSUMED_ROLE_ARN)

        assert result == UNATTRIBUTED_TEAM


# --------------------------------------------------------------------------- #
# AuthService integration: flag gating + non-blocking guarantee
# --------------------------------------------------------------------------- #


def _auth_service():
    mock_secrets_service = MagicMock()
    mock_secrets_service.boto_session = MagicMock()
    mock_secrets_service.fetch_secret = AsyncMock(return_value="sk-test")
    mock_cache_service = MagicMock()
    mock_cache_service.get_cached_auth_result = AsyncMock(return_value=None)
    mock_cache_service.cache_auth_result = AsyncMock(return_value=True)
    mock_validation_service = MagicMock()
    mock_validation_service.validate_and_extract_api_key = MagicMock(
        return_value=("sk-test", None)
    )
    mock_team_service = MagicMock()
    mock_team_service.resolve_teams = AsyncMock(return_value="chembio")

    service = AuthService(
        secrets_service=mock_secrets_service,
        cache_service=mock_cache_service,
        validation_service=mock_validation_service,
        team_service=mock_team_service,
    )
    return service, mock_team_service


def _patch_identity(service):
    """Patch get_aws_identity to return a fixed principal."""
    service.get_aws_identity = AsyncMock(
        return_value=PrincipalInfo(
            arn=ASSUMED_ROLE_ARN,
            account_id="123456789012",
            principal="assumed-role/UserProfile_Alice_chembio",
            session_name="session-1",
            project="chembio",
        )
    )


@pytest.fixture
def auth_payload():
    payload = MagicMock()
    payload.raw = ""  # skip the read-through auth cache branch
    payload.credentials = AwsCredentials(
        access_key_id="AKIATEST123",
        secret_access_key="secretkey123",
        session_token="sessiontoken123",
    )
    payload.secret_arn = "arn:aws:secretsmanager:eu-west-2:1:secret:projects/x/key-aB"
    return payload


class TestAuthServiceTeamStamping:
    @pytest.mark.asyncio
    async def test_flag_off_is_noop(self, auth_payload):
        """Flag off: no team resolution call, teams stays None."""
        service, mock_team_service = _auth_service()
        _patch_identity(service)

        with patch("portunus.services.auth_service.config") as cfg:
            cfg.team_stamping_enabled = False
            result = await service.authenticate(auth_payload, "req-1")

        mock_team_service.resolve_teams.assert_not_called()
        assert result.principal_info.teams is None

    @pytest.mark.asyncio
    async def test_flag_on_stamps_teams(self, auth_payload):
        """Flag on: resolved teams are stamped onto principal_info."""
        service, mock_team_service = _auth_service()
        _patch_identity(service)

        with patch("portunus.services.auth_service.config") as cfg:
            cfg.team_stamping_enabled = True
            result = await service.authenticate(auth_payload, "req-1")

        mock_team_service.resolve_teams.assert_awaited_once()
        assert result.principal_info.teams == "chembio"

    @pytest.mark.asyncio
    async def test_resolution_never_breaks_auth(self, auth_payload):
        """Even if team resolution raised, auth must still succeed.

        resolve_teams swallows its own errors, but we also assert here that the
        AuthService does not depend on its result to produce a valid api key.
        """
        service, mock_team_service = _auth_service()
        # Simulate the service itself returning the sentinel after an internal error.
        mock_team_service.resolve_teams = AsyncMock(return_value=UNATTRIBUTED_TEAM)
        _patch_identity(service)

        with patch("portunus.services.auth_service.config") as cfg:
            cfg.team_stamping_enabled = True
            result = await service.authenticate(auth_payload, "req-1")

        assert result.successful
        assert result.api_key == "sk-test"
        assert result.principal_info.teams == UNATTRIBUTED_TEAM


# --------------------------------------------------------------------------- #
# MetadataRecord carries teams end-to-end
# --------------------------------------------------------------------------- #


class TestMetadataRecordTeams:
    def test_to_dict_includes_teams(self):
        record = MetadataRecord(
            request_id="r",
            timestamp="t",
            published_at="p",
            teams="chembio,soe",
        )
        assert record.to_dict()["teams"] == "chembio,soe"

    def test_teams_nullable_for_backcompat(self):
        record = MetadataRecord(request_id="r", timestamp="t", published_at="p")
        assert record.to_dict()["teams"] is None

    def test_principal_info_roundtrip(self):
        info = PrincipalInfo.from_dict(
            {
                "arn": ASSUMED_ROLE_ARN,
                "account_id": "123456789012",
                "principal": "assumed-role/x",
                "session_name": "s",
                "project": "chembio",
                "teams": "chembio,soe",
            }
        )
        assert info.teams == "chembio,soe"

    def test_principal_info_legacy_dict_without_teams(self):
        """Records cached before this field must still deserialize."""
        info = PrincipalInfo.from_dict(
            {
                "arn": ASSUMED_ROLE_ARN,
                "account_id": "123456789012",
                "principal": "assumed-role/x",
                "session_name": "s",
                "project": "chembio",
            }
        )
        assert info.teams is None
