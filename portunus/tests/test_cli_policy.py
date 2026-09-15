"""Tests for the default session policy the CLI attaches to encoded credentials."""

import json

import pytest

from portunus.cli import _build_default_policy, _federation_role_pattern

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
SECRET_PREFIX = f"arn:aws:secretsmanager:eu-west-2:{ACCOUNT}:secret:"
SECRET_ARN = f"{SECRET_PREFIX}projects/example/example-grant-AbCdEf"
FLAT_SECRET_ARN = f"{SECRET_PREFIX}test-api-key-AbCdEf"


def _statements(policy_json: str) -> dict[str, dict]:
    return {
        statement["Sid"]: statement
        for statement in json.loads(policy_json)["Statement"]
    }


def test_default_policy_grants_the_secret_kms_sign_and_the_namespace_roles():
    policy = json.loads(_build_default_policy(SECRET_ARN, ACCOUNT))
    statements = _statements(json.dumps(policy))

    assert policy["Version"] == "2012-10-17"
    assert list(statements) == [
        "SecretsManagerAccess",
        "KMSSignAccess",
        "PortunusFederationAssumeRole",
    ]
    assert statements["SecretsManagerAccess"]["Action"] == [
        "secretsmanager:GetSecretValue"
    ]
    assert statements["SecretsManagerAccess"]["Resource"] == SECRET_ARN
    assert statements["KMSSignAccess"]["Action"] == ["kms:Sign"]
    assert statements["KMSSignAccess"]["Resource"] == "*"
    federation = statements["PortunusFederationAssumeRole"]
    assert federation["Effect"] == "Allow"
    assert federation["Action"] == ["sts:AssumeRole"]
    assert (
        federation["Resource"]
        == f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/*"
    )


def test_secret_outside_a_namespace_gets_no_assume_role_statement():
    statements = _statements(_build_default_policy(FLAT_SECRET_ARN, ACCOUNT))

    assert list(statements) == ["SecretsManagerAccess", "KMSSignAccess"]
    assert statements["SecretsManagerAccess"]["Resource"] == FLAT_SECRET_ARN
    assert statements["KMSSignAccess"]["Resource"] == "*"
    assert all(
        "sts:AssumeRole" not in statement["Action"] for statement in statements.values()
    )


def test_roles_are_in_the_callers_account_not_the_secrets():
    secret_arn = (
        f"arn:aws:secretsmanager:eu-west-2:{OTHER_ACCOUNT}:secret:"
        "projects/example/example-grant-AbCdEf"
    )
    statements = _statements(_build_default_policy(secret_arn, ACCOUNT))

    assert (
        statements["PortunusFederationAssumeRole"]["Resource"]
        == f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/projects/example/*"
    )


def test_federation_role_path_is_configurable():
    statements = _statements(_build_default_policy(SECRET_ARN, ACCOUNT, "/custom-fed/"))

    assert (
        statements["PortunusFederationAssumeRole"]["Resource"]
        == f"arn:aws:iam::{ACCOUNT}:role/custom-fed/projects/example/*"
    )


@pytest.mark.parametrize(
    ("secret_name", "namespace"),
    [
        ("projects/example/example-grant-AbCdEf", "projects/example"),
        ("users/some-user/grant/nested-AbCdEf", "users/some-user"),
        ("teams/a-team/g", "teams/a-team"),
        ("Type.1/a_b+c=d@e/grant-AbCdEf", "Type.1/a_b+c=d@e"),
    ],
)
def test_namespace_is_the_first_two_segments_of_the_secret_name(
    secret_name: str, namespace: str
):
    pattern = _federation_role_pattern(
        SECRET_PREFIX + secret_name, ACCOUNT, "/portunus-fed/"
    )

    assert pattern == f"arn:aws:iam::{ACCOUNT}:role/portunus-fed/{namespace}/*"


@pytest.mark.parametrize(
    "secret_arn",
    [
        f"{SECRET_PREFIX}test-api-key-AbCdEf",
        f"{SECRET_PREFIX}projects/example-AbCdEf",
        f"{SECRET_PREFIX}projects//grant-AbCdEf",
        f"{SECRET_PREFIX}/projects/example/grant-AbCdEf",
        SECRET_PREFIX,
        "arn:aws:secretsmanager:eu-west-2:123456789012:projects/example/grant",
        "not-an-arn",
        "",
    ],
)
def test_names_with_fewer_than_two_leading_segments_have_no_pattern(
    secret_arn: str,
):
    assert _federation_role_pattern(secret_arn, ACCOUNT, "/portunus-fed/") is None
