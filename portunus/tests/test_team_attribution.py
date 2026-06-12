"""Tests for live team resolution + stamping (feature-flagged, default off).

Tags are read via a Portunus-held reader role (assumed with Portunus's own task
creds, session cached/reused), NOT the caller's credentials.

Covers:
    * `teams` tag parsing (comma-split, whitespace, empty).
    * The `__unattributed__` sentinel on every failure path (missing/garbled
      tag, ListRoleTags failure, AssumeRole failure, no reader role configured).
    * roleArn->teams cache set / get / expiry (separate from the auth cache).
    * ARN -> role-name extraction.
    * Reader STS session is assumed once and reused (not per request).
    * Flag-off no-op: no assume-role/IAM call, principal_info.teams untouched.
    * A tag-read exception does not break authentication.
"""

from datetime import datetime, timedelta, timezone
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


READER_ROLE_ARN = "arn:aws:iam::302000000000:role/PortunusTeamTagReader"


def _async_client_cm(client):
    """Wrap a mock client as an async context manager (matches create_client)."""
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _assume_role_response(expires_in_seconds: int = 3600):
    """Build a fake STS AssumeRole response with an expiry in the future."""
    return {
        "Credentials": {
            "AccessKeyId": "ASIAREADER",
            "SecretAccessKey": "readersecret",
            "SessionToken": "readertoken",
            "Expiration": datetime.now(timezone.utc)
            + timedelta(seconds=expires_in_seconds),
        }
    }


def _team_service_with_reader(
    cache,
    tags=None,
    *,
    assume_role_side_effect=None,
    list_tags_side_effect=None,
):
    """Build a TeamService whose reader-role STS + IAM clients are mocked.

    The session's create_client dispatches by service name: "sts" returns the
    AssumeRole client, "iam" returns the ListRoleTags client. This mirrors the
    own-identity flow (assume reader role, then call IAM with that session).
    """
    service = TeamService(cache_service=cache)

    sts_client = AsyncMock()
    if assume_role_side_effect is not None:
        sts_client.assume_role = AsyncMock(side_effect=assume_role_side_effect)
    else:
        sts_client.assume_role = AsyncMock(return_value=_assume_role_response())
    _async_client_cm(sts_client)

    iam_client = AsyncMock()
    if list_tags_side_effect is not None:
        iam_client.list_role_tags = AsyncMock(side_effect=list_tags_side_effect)
    else:
        iam_client.list_role_tags = AsyncMock(return_value={"Tags": tags or []})
    _async_client_cm(iam_client)

    def _create_client(service_name, *args, **kwargs):
        return sts_client if service_name == "sts" else iam_client

    service.boto_session = MagicMock()
    service.boto_session.create_client = MagicMock(side_effect=_create_client)
    return service, sts_client, iam_client


@pytest.fixture(autouse=True)
def reader_role_configured():
    """Configure the reader role ARN for team_service.config by default."""
    with patch("portunus.services.team_service.config") as cfg:
        cfg.team_tag_reader_role_arn = READER_ROLE_ARN
        cfg.team_tag_reader_region = "eu-west-2"
        cfg.aws.endpoint_url = None
        cfg.team_cache_ttl = 3600
        yield cfg


class TestResolveTeams:
    @pytest.mark.asyncio
    async def test_resolves_and_caches(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, _sts, _iam = _team_service_with_reader(
            cache, [{"Key": "teams", "Value": "chembio,soe"}]
        )

        result = await service.resolve_teams(ASSUMED_ROLE_ARN)

        assert result == "chembio,soe"
        # cached under the role ARN for next time
        assert await cache.get_cached_teams(EXPECTED_ROLE_ARN) == "chembio,soe"

    @pytest.mark.asyncio
    async def test_reader_session_reused_across_requests(self, fake_redis):
        """AssumeRole happens once and the session is reused (not per request)."""
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, sts_client, iam_client = _team_service_with_reader(
            cache, [{"Key": "teams", "Value": "chembio"}]
        )
        other_arn = (
            "arn:aws:sts::123456789012:assumed-role/UserProfile_Bob_soe/session-2"
        )

        await service.resolve_teams(ASSUMED_ROLE_ARN)
        await service.resolve_teams(other_arn)

        # Two distinct roles -> two IAM reads, but only one AssumeRole.
        assert iam_client.list_role_tags.await_count == 2
        sts_client.assume_role.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cache_hit_skips_iam(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        await cache.cache_teams(EXPECTED_ROLE_ARN, "chembio")
        service, sts_client, iam_client = _team_service_with_reader(cache, [])

        result = await service.resolve_teams(ASSUMED_ROLE_ARN)

        assert result == "chembio"
        iam_client.list_role_tags.assert_not_called()
        sts_client.assume_role.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_tag_is_unattributed(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, _sts, _iam = _team_service_with_reader(
            cache, [{"Key": "owner", "Value": "someone"}]
        )

        result = await service.resolve_teams(ASSUMED_ROLE_ARN)

        assert result == UNATTRIBUTED_TEAM

    @pytest.mark.asyncio
    async def test_unparseable_arn_is_unattributed(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, sts_client, iam_client = _team_service_with_reader(cache, [])

        result = await service.resolve_teams("arn:aws:iam::1:user/bob")

        assert result == UNATTRIBUTED_TEAM
        sts_client.assume_role.assert_not_called()
        iam_client.list_role_tags.assert_not_called()

    @pytest.mark.asyncio
    async def test_iam_exception_is_unattributed(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, _sts, _iam = _team_service_with_reader(
            cache, list_tags_side_effect=Exception("AccessDenied")
        )

        result = await service.resolve_teams(ASSUMED_ROLE_ARN)

        assert result == UNATTRIBUTED_TEAM

    @pytest.mark.asyncio
    async def test_assume_role_failure_is_unattributed(self, fake_redis):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        service, _sts, iam_client = _team_service_with_reader(
            cache, assume_role_side_effect=Exception("AccessDenied on AssumeRole")
        )

        result = await service.resolve_teams(ASSUMED_ROLE_ARN)

        assert result == UNATTRIBUTED_TEAM
        # Never reached the IAM read because assume-role failed first.
        iam_client.list_role_tags.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_reader_role_configured_is_unattributed(
        self, fake_redis, reader_role_configured
    ):
        cache = CacheService(state_service=FakeStateService(fake_redis))
        reader_role_configured.team_tag_reader_role_arn = None
        service, _sts, iam_client = _team_service_with_reader(cache, [])

        result = await service.resolve_teams(ASSUMED_ROLE_ARN)

        assert result == UNATTRIBUTED_TEAM
        iam_client.list_role_tags.assert_not_called()


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
