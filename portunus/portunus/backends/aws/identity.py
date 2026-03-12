"""AWS identity parsing with configurable role pattern.

Extracts principal information from AWS ARNs. The project extraction
pattern is configurable via AWS_IDENTITY_ROLE_PATTERN to support
different role naming conventions across organisations.
"""

import logging
import re
from typing import Optional

from portunus.models import PrincipalInfo

logger = logging.getLogger("api.access")


def extract_arn_parts(arn: str) -> tuple[str, Optional[list[str]]]:
    """Extract account ID and path parts from an AWS ARN.

    Args:
        arn: The AWS ARN to parse.

    Returns:
        Tuple of (account_id, path_parts). account_id defaults
        to "unknown" for invalid ARNs.
    """
    account_id = "unknown"
    path_parts = None
    if arn and ":" in arn:
        parts = arn.split(":")
        if len(parts) >= 5:
            account_id = parts[4]
        if len(parts) >= 6 and "/" in parts[5]:
            resource_parts = parts[5].split("/", 1)
            if len(resource_parts) > 1:
                path_parts = resource_parts[1].split("/")
    return account_id, path_parts


def get_role_arn(session_arn: str) -> str:
    """Extract the role ARN from an assumed-role session ARN.

    Args:
        session_arn: The ARN of the assumed-role session.

    Returns:
        The reconstructed IAM role ARN.
    """
    account_id, path_parts = extract_arn_parts(session_arn)
    if path_parts and len(path_parts) > 0:
        role_name = path_parts[0]
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    role_name = session_arn.split("/")[1]
    account_id = session_arn.split(":")[4]
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def parse_identity_from_arn(
    arn: str,
    role_pattern: Optional[str] = None,
) -> PrincipalInfo:
    """Extract identity information from an AWS ARN.

    Args:
        arn: The AWS ARN to parse.
        role_pattern: Optional regex with named groups applied to
            the role name. Supported groups: ``project``. If None,
            no project extraction is attempted.

    Returns:
        PrincipalInfo with extracted identity fields.
    """
    account_id, path_parts = extract_arn_parts(arn)

    principal = None
    session_name = None
    project = None

    if "assumed-role" in arn and path_parts and len(path_parts) >= 2:
        role_name = path_parts[0]
        principal = f"assumed-role/{role_name}"
        session_name = path_parts[1]

        # Apply configurable role pattern for project extraction
        if role_pattern:
            match = re.match(role_pattern, role_name)
            if match:
                groups = match.groupdict()
                project = groups.get("project")
    else:
        logger.warning(f"Unrecognized ARN format: {arn}")

    return PrincipalInfo(
        arn=arn,
        account_id=account_id,
        principal=principal,
        session_name=session_name,
        project=project,
    )
