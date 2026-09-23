"""Tests for the CLI's encode-credentials command."""

import json
import sys

import pytest

from portunus import cli
from portunus.cli import _build_default_policy
from portunus.services.payload_service import decode_payload

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


class _FakeSts:
    def __init__(self) -> None:
        self.assume_role_kwargs: dict = {}

    def get_caller_identity(self) -> dict:
        return {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/ExampleRole/session"}

    def assume_role(self, **kwargs) -> dict:
        self.assume_role_kwargs = kwargs
        return {
            "Credentials": {
                "AccessKeyId": "AKIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": "2026-01-01T12:00:00+00:00",
            }
        }


@pytest.fixture
def sts(monkeypatch: pytest.MonkeyPatch) -> _FakeSts:
    fake = _FakeSts()
    monkeypatch.setattr(cli.boto3, "client", lambda service: fake)
    return fake


def _run_encode(monkeypatch: pytest.MonkeyPatch, *argv: str) -> None:
    monkeypatch.setattr(
        sys, "argv", ["portunus", "encode-credentials", SECRET_ARN, *argv]
    )
    cli.main()


def test_session_name_defaults_to_portunus(
    sts: _FakeSts, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
):
    _run_encode(monkeypatch)

    assert sts.assume_role_kwargs["RoleSessionName"] == "portunus"
    assert (
        sts.assume_role_kwargs["RoleArn"] == f"arn:aws:iam::{ACCOUNT}:role/ExampleRole"
    )
    payload = decode_payload(capsys.readouterr().out.strip())
    assert payload["secret_arn"] == SECRET_ARN
    assert payload["credentials"]["session_token"] == "token"


@pytest.mark.parametrize(
    "name", ["portunus-vm", "ab", "a" * 64, "user@example.com", "a+=,.@-_z"]
)
def test_session_name_option_reaches_assume_role(
    sts: _FakeSts, monkeypatch: pytest.MonkeyPatch, name: str
):
    _run_encode(monkeypatch, "--session-name", name)

    assert sts.assume_role_kwargs["RoleSessionName"] == name


@pytest.mark.parametrize(
    "name", ["", "x", "a" * 65, "has space", "slash/name", "colon:name", "caf\u00e9"]
)
def test_invalid_session_name_is_rejected_before_calling_sts(
    sts: _FakeSts,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    name: str,
):
    with pytest.raises(SystemExit) as excinfo:
        _run_encode(monkeypatch, "--session-name", name)

    assert excinfo.value.code == 2
    assert "is not a valid role session name" in capsys.readouterr().err
    assert sts.assume_role_kwargs == {}
