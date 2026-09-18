"""Tests for the default session policy the CLI attaches to encoded credentials."""

import json

import pytest

from portunus.cli import _build_default_policy

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
SECRET_PREFIX = f"arn:aws:secretsmanager:eu-west-2:{ACCOUNT}:secret:"
SECRET_ARN = f"{SECRET_PREFIX}projects/example/example-grant-AbCdEf"
FEDERATION_ROLES = f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/*"


def _statements(policy_json: str) -> dict[str, dict]:
    return {
        statement["Sid"]: statement
        for statement in json.loads(policy_json)["Statement"]
    }


def test_default_policy_grants_the_secret_and_the_federation_roles():
    policy = json.loads(_build_default_policy(SECRET_ARN, ACCOUNT))
    statements = _statements(json.dumps(policy))

    assert policy["Version"] == "2012-10-17"
    assert list(statements) == ["SecretsManagerAccess", "PortunusFederationAssumeRole"]
    assert statements["SecretsManagerAccess"]["Action"] == [
        "secretsmanager:GetSecretValue"
    ]
    assert statements["SecretsManagerAccess"]["Resource"] == SECRET_ARN
    federation = statements["PortunusFederationAssumeRole"]
    assert federation["Effect"] == "Allow"
    assert federation["Action"] == ["sts:AssumeRole"]
    assert federation["Resource"] == FEDERATION_ROLES


@pytest.mark.parametrize(
    "secret_arn",
    [
        SECRET_ARN,
        f"{SECRET_PREFIX}test-api-key-AbCdEf",
        f"{SECRET_PREFIX}projects/*/grant-AbCdEf",
        f"arn:aws:secretsmanager:eu-west-2:{OTHER_ACCOUNT}:secret:projects/example/g",
        "not-an-arn",
    ],
)
def test_federation_grant_does_not_depend_on_the_secret(secret_arn: str):
    statements = _statements(_build_default_policy(secret_arn, ACCOUNT))

    assert statements["SecretsManagerAccess"]["Resource"] == secret_arn
    assert statements["PortunusFederationAssumeRole"]["Resource"] == FEDERATION_ROLES


def test_federation_role_path_is_configurable():
    statements = _statements(_build_default_policy(SECRET_ARN, ACCOUNT, "/custom-fed/"))

    assert (
        statements["PortunusFederationAssumeRole"]["Resource"]
        == f"arn:aws:iam::{ACCOUNT}:role/custom-fed/*"
    )
