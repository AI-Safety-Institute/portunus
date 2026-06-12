"""
Team resolution service module.

This module resolves the caller's team membership from the IAM role's ``teams``
tag and is used to stamp live, on-record team attribution onto published log
metadata. It exists to support the "tag -> stamp -> filter" fix for cross-team
log attribution: roles are tagged ``teams=<slugs>`` (in a separate change),
Portunus stamps the resolved team(s) onto the metadata record here, and the
downstream Glue views filter on that live, on-record value.

Design (see the team-attribution design doc):
    * Tags are read AS PORTUNUS ITSELF, via a Portunus-held cross-account reader
      role (``PortunusTeamTagReader`` in the identity account, 302). Portunus
      assumes that role with its own task credentials and reuses the assumed STS
      session until shortly before it expires - it is NOT assumed per request.
      This is deliberate: the caller's credentials are scoped down by aisitools
      session policies that strip ``iam:ListRoleTags``, so reading as the caller
      would fail-safe to ``__unattributed__`` for all scoped traffic. Reading via
      a Portunus-held role is immune to that scoping and decouples team fetching
      from the request path. The caller's credentials are still used only for the
      existing ``sts:GetCallerIdentity`` call (to derive the principal/role name).
    * ``roleArn -> teams`` is cached in Redis with a ~1h TTL, keyed on the role
      ARN, separate from the payload-keyed auth cache.
    * Tag scope is all teams (the full ``teams`` tag value, comma-split).
    * Fail-mode is quarantine: on any error (assume-role failure, ListRoleTags
      failure, missing/unparseable role or tag) the result is the
      ``__unattributed__`` sentinel.
    * Resolution is best-effort metadata only - it MUST NEVER block, deny, or
      error the proxied request. Every failure path returns the sentinel.

The entire feature is gated behind ``config.team_stamping_enabled`` (default
off); callers should not invoke this service when the flag is disabled.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from aiobotocore.session import get_session

from portunus.config import config
from portunus.models import (
    TEAMS_DELIMITER,
    UNATTRIBUTED_TEAM,
    AwsCredentials,
)
from portunus.services.arn_service import extract_role_name, get_role_arn
from portunus.services.cache_service import CacheService

logger = logging.getLogger("api.access")

# Name of the IAM role tag carrying the team slugs.
TEAMS_TAG_KEY = "teams"

# Session name used when assuming the reader role (visible in CloudTrail).
READER_SESSION_NAME = "portunus-team-tag-reader"

# Refresh the assumed reader session this long before it actually expires, so a
# request never picks up credentials that expire mid-call.
SESSION_REFRESH_SKEW = timedelta(minutes=5)


def parse_teams_tag(tag_value: Optional[str]) -> List[str]:
    """Parse the ``teams`` tag value into a list of team slugs.

    The tag value is a delimited list of slugs (e.g. ``"team-a,team-b"``).
    Empty / whitespace-only entries are dropped. Returns an empty list when the
    tag is missing or contains no usable slugs (the caller then applies the
    unattributed sentinel).

    Args:
        tag_value: The raw value of the ``teams`` tag, or None.

    Returns:
        List of non-empty, stripped team slugs (order preserved).
    """
    if not tag_value:
        return []
    return [slug.strip() for slug in tag_value.split(",") if slug.strip()]


def teams_to_delimited(teams: List[str]) -> str:
    """Flatten a list of team slugs into the stored delimited string.

    Falls back to the unattributed sentinel for an empty list so the stored
    value is always meaningful for downstream filtering.

    Args:
        teams: List of team slugs.

    Returns:
        Delimited team string, or the unattributed sentinel if empty.
    """
    if not teams:
        return UNATTRIBUTED_TEAM
    return TEAMS_DELIMITER.join(teams)


class TeamService:
    """Resolve and cache team membership from the role's ``teams`` tag.

    Tags are read using a Portunus-held cross-account reader role (assumed with
    Portunus's own task credentials), whose STS session is cached in-memory and
    reused across requests until shortly before it expires.

    Attributes:
        cache_service: CacheService used for the roleArn->teams cache.
        boto_session: aiobotocore session created from Portunus's own task
            credentials (used to assume the reader role and call IAM).
    """

    def __init__(self, cache_service: Optional[CacheService] = None):
        """Initialize the TeamService."""
        self.cache_service = cache_service or CacheService()
        self.boto_session = get_session()
        # Cached assumed-reader-role credentials, reused until near expiry.
        self._reader_credentials: Optional[AwsCredentials] = None
        # Serialise concurrent refreshes so only one AssumeRole happens at a time.
        self._reader_lock = asyncio.Lock()

    def _reader_credentials_valid(self) -> bool:
        """Return True if cached reader credentials exist and are not near expiry."""
        creds = self._reader_credentials
        if creds is None or not creds.expiration:
            return False
        return datetime.now(timezone.utc) < creds.expiration - SESSION_REFRESH_SKEW

    async def _assume_reader_role(self) -> AwsCredentials:
        """Assume the Portunus reader role and return its temporary credentials.

        Uses Portunus's own task credentials (the default session) to call STS
        AssumeRole against ``config.team_tag_reader_role_arn``.

        Returns:
            AwsCredentials for the assumed reader session.

        Raises:
            RuntimeError: If no reader role ARN is configured.
            Exception: Any STS error is propagated to the caller, which treats it
                as unattributed.
        """
        role_arn = config.team_tag_reader_role_arn
        if not role_arn:
            raise RuntimeError("team_tag_reader_role_arn is not configured")

        async with self.boto_session.create_client(
            "sts",
            region_name=config.team_tag_reader_region,
            endpoint_url=config.aws.endpoint_url,
        ) as sts_client:
            response = await sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=READER_SESSION_NAME,
            )
        creds = response["Credentials"]
        expiration = creds.get("Expiration")
        # botocore returns Expiration as a tz-aware datetime; normalise to UTC.
        if isinstance(expiration, datetime) and expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        return AwsCredentials(
            access_key_id=creds["AccessKeyId"],
            secret_access_key=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
            expiration=expiration,
        )

    async def _get_reader_credentials(self) -> AwsCredentials:
        """Return cached reader credentials, refreshing them only when near expiry.

        The AssumeRole call is performed at most once per session lifetime (minus
        the refresh skew), not per request, and is guarded by a lock so a burst of
        concurrent requests triggers only a single refresh.
        """
        if self._reader_credentials_valid():
            return self._reader_credentials  # type: ignore[return-value]  # guarded by _reader_credentials_valid
        async with self._reader_lock:
            # Re-check inside the lock: another coroutine may have refreshed.
            if self._reader_credentials_valid():
                return self._reader_credentials  # type: ignore[return-value]  # guarded by _reader_credentials_valid
            self._reader_credentials = await self._assume_reader_role()
            return self._reader_credentials

    async def _list_role_tags_as_reader(self, role_name: str) -> Optional[str]:
        """Call ``iam:ListRoleTags`` using the assumed reader session.

        Args:
            role_name: The IAM role name to read tags from.

        Returns:
            The raw ``teams`` tag value, or None if absent.

        Raises:
            Exception: Propagated to the caller, which treats any failure as
                unattributed. This method does not swallow errors itself.
        """
        reader = await self._get_reader_credentials()
        async with self.boto_session.create_client(
            "iam",
            region_name=config.team_tag_reader_region,
            aws_access_key_id=reader.access_key_id,
            aws_secret_access_key=reader.secret_access_key,
            aws_session_token=reader.session_token,
            endpoint_url=config.aws.endpoint_url,
        ) as iam_client:
            response = await iam_client.list_role_tags(RoleName=role_name)
        for tag in response.get("Tags", []):
            if tag.get("Key") == TEAMS_TAG_KEY:
                return tag.get("Value")
        return None

    async def resolve_teams(self, principal_arn: str) -> str:
        """Resolve the caller's team(s) as a delimited string for stamping.

        Resolution order:
            1. Derive the role name from the principal ARN.
            2. On a roleArn->teams cache hit, return the cached value.
            3. On a miss, read the role's ``teams`` tag using the Portunus reader
               role (reusing the cached assumed session), parse it, cache the
               result (~1h TTL), and return it.

        This method is non-blocking by contract: any error (assume-role failure,
        ListRoleTags failure, missing tag, or unparseable ARN) yields the
        ``__unattributed__`` sentinel rather than raising. It is safe to call
        without a try/except around it, but callers should still treat team
        resolution as advisory metadata only.

        Args:
            principal_arn: The caller's assumed-role session ARN (from STS
                GetCallerIdentity).

        Returns:
            Delimited teams string, or ``__unattributed__`` on any failure.
        """
        try:
            role_name = extract_role_name(principal_arn)
            if not role_name:
                logger.warning(
                    f"Could not derive role name from ARN for team stamping: "
                    f"{principal_arn}"
                )
                return UNATTRIBUTED_TEAM

            role_arn = get_role_arn(principal_arn)

            cached = await self.cache_service.get_cached_teams(role_arn)
            if cached is not None:
                return cached

            tag_value = await self._list_role_tags_as_reader(role_name)
            teams = parse_teams_tag(tag_value)
            resolved = teams_to_delimited(teams)

            # Cache even the sentinel so we don't hammer IAM for untagged roles.
            await self.cache_service.cache_teams(role_arn, resolved)
            return resolved
        except Exception as e:
            # Quarantine on any failure; never propagate to the request path.
            logger.error(f"Team resolution failed for {principal_arn}: {e}")
            return UNATTRIBUTED_TEAM
