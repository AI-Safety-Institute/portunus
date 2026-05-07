"""Tests for the parse_identity_from_arn function in the ARN service module."""

from portunus.services.arn_service import parse_identity_from_arn


def test_parse_identity_from_empty_arn():
    """Test parsing an empty ARN string."""
    result = parse_identity_from_arn("")
    assert result.account_id == "unknown"
    assert result.principal is None
    assert result.session_name is None
    assert result.project == "unknown"


def test_parse_identity_from_invalid_arn():
    """Test parsing an invalid ARN string."""
    result = parse_identity_from_arn("invalid-arn")
    assert result.account_id == "unknown"
    assert result.principal is None
    assert result.session_name is None
    assert result.project == "unknown"


def test_parse_identity_from_iam_user_arn():
    """Test parsing an IAM user ARN with no explicit path."""
    result = parse_identity_from_arn("arn:aws:iam::123456789012:user/test-user")
    assert result.account_id == "123456789012"
    assert result.principal == "user/test-user"
    assert result.session_name is None
    assert result.project == "unknown"


def test_parse_identity_from_iam_user_arn_with_path():
    """Test parsing an IAM user ARN with a multi-segment path.

    AWS IAM users may be provisioned at arbitrary slash-separated paths.
    The full path-and-name must be preserved so downstream attribution
    stays distinguishable across users at different paths.
    """
    arn = "arn:aws:iam::123456789012:user/some-path/example-user"
    result = parse_identity_from_arn(arn)
    assert result.account_id == "123456789012"
    assert result.principal == "user/some-path/example-user"
    assert result.session_name is None
    assert result.project == "unknown"


def test_parse_identity_from_assumed_role_arn():
    """Test parsing an assumed role ARN."""
    result = parse_identity_from_arn(
        "arn:aws:sts::123456789012:assumed-role/RoleName/session-name"
    )
    assert result.account_id == "123456789012"
    assert result.principal == "assumed-role/RoleName"
    assert result.session_name == "session-name"
    assert result.project == "unknown"


def test_parse_identity_from_userprofile_role_arn():
    """Test parsing an assumed role ARN with UserProfile pattern."""
    result = parse_identity_from_arn(
        "arn:aws:sts::123456789012:assumed-role/UserProfile_Name_project/session-name"
    )
    assert result.account_id == "123456789012"
    assert result.principal == "assumed-role/UserProfile_Name_project"
    assert result.session_name == "session-name"
    assert result.project == "project"


def test_parse_identity_from_userprofile_role_arn_multiple_projects():
    """Test parsing an assumed role ARN with UserProfile pattern."""
    result = parse_identity_from_arn(
        "arn:aws:sts::123456789012:assumed-role/UserProfile_Name_project_abc/session-name"
    )
    assert result.account_id == "123456789012"
    assert result.principal == "assumed-role/UserProfile_Name_project_abc"
    assert result.session_name == "session-name"
    assert result.project == "project_abc"


def test_parse_identity_from_malformed_assumed_role_arn():
    """Test parsing a malformed assumed role ARN without enough segments."""
    result = parse_identity_from_arn("arn:aws:sts::123456789012:assumed-role/RoleName")
    assert result.account_id == "123456789012"
    assert result.principal is None
    assert result.session_name is None
    assert result.project == "unknown"
