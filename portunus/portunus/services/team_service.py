"""
Team resolution service module.

This module resolves the caller's team membership from the IAM role's ``teams``
tag and is used to stamp live, on-record team attribution onto published log
metadata. It exists to support the "tag -> stamp -> filter" fix for cross-team
log attribution: roles are tagged ``teams=<slugs>`` (in a separate change),
Portunus stamps the resolved team(s) onto the metadata record here, and the
downstream Glue views filter on that live, on-record value.

Design (see the team-attribution design doc):
    * Tags are read AS THE CALLER, reusing the same ``AwsCredentials`` already
      used for the STS ``GetCallerIdentity`` call - no Portunus-owned IAM perms.
    * ``roleArn -> teams`` is cached in Redis with a ~1h TTL, keyed on the role
      ARN, separate from the payload-keyed auth cache.
    * Tag scope is all teams (the full ``teams`` tag value, comma-split).
    * Fail-mode is quarantine: on any error / missing tag / unparseable role the
      result is the ``__unattributed__`` sentinel.
    * Resolution is best-effort metadata only - it MUST NEVER block, deny, or
      error the proxied request. Every failure path returns the sentinel.

The entire feature is gated behind ``config.team_stamping_enabled`` (default
off); callers should not invoke this service when the flag is disabled.
"""

import logging
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
    """Resolve and cache the caller's team membership from the role tag.

    Attributes:
        cache_service: CacheService used for the roleArn->teams cache.
        boto_session: aiobotocore session used to create IAM clients with the
            caller's credentials.
    """

    def __init__(self, cache_service: Optional[CacheService] = None):
        """Initialize the TeamService."""
        self.cache_service = cache_service or CacheService()
        self.boto_session = get_session()

    async def _list_role_tags_as_caller(
        self, credentials: AwsCredentials, role_name: str
    ) -> Optional[str]:
        """Call ``iam:ListRoleTags`` as the caller and return the teams tag value.

        Uses the caller's own credentials (the same creds used for the STS call)
        so no Portunus-owned IAM permissions are required.

        Args:
            credentials: The caller's AWS credentials.
            role_name: The IAM role name to read tags from.

        Returns:
            The raw ``teams`` tag value, or None if absent.

        Raises:
            Exception: Propagated to the caller, which treats any failure as
                unattributed. This method does not swallow errors itself.
        """
        async with self.boto_session.create_client(
            "iam",
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            endpoint_url=config.aws.endpoint_url,
        ) as iam_client:
            response = await iam_client.list_role_tags(RoleName=role_name)
        for tag in response.get("Tags", []):
            if tag.get("Key") == TEAMS_TAG_KEY:
                return tag.get("Value")
        return None

    async def resolve_teams(
        self, credentials: AwsCredentials, principal_arn: str
    ) -> str:
        """Resolve the caller's team(s) as a delimited string for stamping.

        Resolution order:
            1. Derive the role name from the principal ARN.
            2. On a roleArn->teams cache hit, return the cached value.
            3. On a miss, read the role's ``teams`` tag as the caller, parse it,
               cache the result (~1h TTL), and return it.

        This method is non-blocking by contract: any error, missing tag, or
        unparseable ARN yields the ``__unattributed__`` sentinel rather than
        raising. It is safe to call without a try/except around it, but callers
        should still treat team resolution as advisory metadata only.

        Args:
            credentials: The caller's AWS credentials (reused from the STS call).
            principal_arn: The caller's assumed-role session ARN.

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

            tag_value = await self._list_role_tags_as_caller(credentials, role_name)
            teams = parse_teams_tag(tag_value)
            resolved = teams_to_delimited(teams)

            # Cache even the sentinel so we don't hammer IAM for untagged roles.
            await self.cache_service.cache_teams(role_arn, resolved)
            return resolved
        except Exception as e:
            # Quarantine on any failure; never propagate to the request path.
            logger.error(f"Team resolution failed for {principal_arn}: {e}")
            return UNATTRIBUTED_TEAM
