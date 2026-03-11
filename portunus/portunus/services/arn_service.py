"""
ARN handling service module.

This module contains functions for working with AWS ARNs, including parsing
and extracting identity information.
"""

import logging
from typing import Optional, Tuple


def extract_arn_parts(arn: str) -> Tuple[str, Optional[list]]:
    """Extract common parts from an AWS ARN.

    Args:
        arn (str): The AWS ARN to parse.

    Returns:
        Tuple containing:
            - account_id: The AWS account ID (or "unknown" if invalid ARN)
            - path_parts: The path parts after the resource type, if any
    """
    # Default value for invalid ARNs
    account_id = "unknown"
    path_parts = None
    # Parse ARN format: arn:aws:service:region:account-id:resource-type/resource-path
    if arn and ":" in arn:
        parts = arn.split(":")
        if len(parts) >= 5:
            account_id = parts[4]
        # Extract path parts if they exist
        if len(parts) >= 6 and "/" in parts[5]:
            resource_parts = parts[5].split("/", 1)
            if len(resource_parts) > 1:
                path_parts = resource_parts[1].split("/")
    return account_id, path_parts


def get_role_arn(session_arn: str) -> str:
    """Extract the role ARN from the session ARN.

    This works on the assumption that the user is
    accessing AWS via an assumed role, attached to
    an instance profile, which has a corresponding
    role with the same name.

    Args:
        session_arn (str): The ARN of the session.

    Returns:
        str: The ARN of the role.
    """
    account_id, path_parts = extract_arn_parts(session_arn)
    if path_parts and len(path_parts) > 0:
        role_name = path_parts[0]
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    # Fallback to old implementation if parsing fails
    role_name = session_arn.split("/")[1]
    account_id = session_arn.split(":")[4]
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def parse_identity_from_arn(arn: str):
    """Extract identity information from an AWS ARN.

    Extracts account_id, principal, session_name, and project from the ARN.

    Args:
        arn (str): The AWS ARN to parse.

    Returns:
        PrincipalInfo: An object containing identity information:
            - account_id: The AWS account ID
            - principal: The principal type and name
            - session_name: The session name if present
            - project: The project name extracted from UserProfile_ roles
    """
    # Import PrincipalInfo here to avoid circular imports
    from portunus.models import PrincipalInfo

    # Extract the basic ARN parts
    account_id, path_parts = extract_arn_parts(arn)
    # Default values
    principal = None
    session_name = None
    project = None
    # For assumed roles, we need special handling
    # Example: arn:aws:sts::123456789012:assumed-role/UserProfile_Name_project/xx
    if "assumed-role" in arn and path_parts and len(path_parts) >= 2:
        role_name = path_parts[0]
        principal = f"assumed-role/{role_name}"
        session_name = path_parts[1]
        # Extract project from role name (AISI-specific pattern)
        if role_name.startswith("UserProfile_"):
            role_parts = role_name.split("_")
            if len(role_parts) >= 3:
                project = "_".join(role_parts[2:])

    else:
        principal = None
        session_name = None
        project = None
        logging.warning(f"Unrecognized ARN format: {arn}")

    return PrincipalInfo(
        arn=arn,
        account_id=account_id,
        principal=principal,
        session_name=session_name,
        project=project or "unknown",
    )
