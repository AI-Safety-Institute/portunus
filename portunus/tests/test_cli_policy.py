"""Tests for the default session policy the CLI attaches to encoded credentials."""

import json

from portunus.cli import _build_default_policy

SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:test-api-key"


def _statements(policy_json: str) -> dict[str, dict]:
    return {
        statement["Sid"]: statement
        for statement in json.loads(policy_json)["Statement"]
    }


def test_default_policy_allows_assuming_the_callers_federation_roles():
    statements = _statements(_build_default_policy(SECRET_ARN, "123456789012"))

    assert statements["SecretsManagerAccess"]["Resource"] == SECRET_ARN
    assert statements["FederationRoleAccess"]["Action"] == ["sts:AssumeRole"]
    assert (
        statements["FederationRoleAccess"]["Resource"]
        == "arn:aws:iam::123456789012:role/portunus-fed/*"
    )


def test_federation_role_path_is_configurable():
    statements = _statements(
        _build_default_policy(SECRET_ARN, "123456789012", "/custom-fed/")
    )

    assert (
        statements["FederationRoleAccess"]["Resource"]
        == "arn:aws:iam::123456789012:role/custom-fed/*"
    )
