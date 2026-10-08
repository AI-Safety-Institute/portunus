"""Portunus CLI for generating proxy authentication payloads."""

import argparse
import json
import os
import re
import sys

import boto3

from portunus.config import DEFAULT_FEDERATION_ROLE_PATH_PREFIX
from portunus.services.arn_service import extract_arn_parts, get_role_arn
from portunus.services.payload_service import encode_payload

TEMP_CRED_DURATION_SECONDS = 12 * 60 * 60
DEFAULT_SESSION_NAME = "portunus"
# STS's RoleSessionName rule; the charset is ASCII, so re.ASCII keeps \w from
# admitting more.
_ROLE_SESSION_NAME = re.compile(r"^[\w+=,.@-]{2,64}$", re.ASCII)
_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/\S+$", re.ASCII)


def _build_default_policy(
    secret_arn: str,
    account_id: str,
    federation_role_path: str = DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
) -> str:
    """Build the default session policy for one secret.

    Grants GetSecretValue on ``secret_arn`` and sts:AssumeRole/sts:TagSession
    on every federation role under ``federation_role_path`` in the caller's account.
    """
    statements = [
        {
            "Sid": "SecretsManagerAccess",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": secret_arn,
        },
        {
            "Sid": "PortunusFederationAssumeRole",
            "Effect": "Allow",
            # Transitive tags inherited from the caller's session require
            # TagSession even though Portunus passes no explicit Tags.
            "Action": ["sts:AssumeRole", "sts:TagSession"],
            "Resource": f"arn:aws:iam::{account_id}:role{federation_role_path}*",
        },
    ]
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _load_policy(policy_arg: str) -> str:
    """Load a session policy from a file path or inline JSON string."""
    if os.path.isfile(policy_arg):
        with open(policy_arg) as f:
            raw = f.read()
    else:
        raw = policy_arg

    # Validate it's valid JSON
    json.loads(raw)
    return raw


def _session_name(value: str) -> str:
    """Validate a role session name against STS's rule (argparse ``type``)."""
    if not _ROLE_SESSION_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a valid role session name: "
            "2 to 64 characters from [A-Za-z0-9_+=,.@-]"
        )
    return value


def _role_arn(value: str) -> str:
    """Validate an IAM role ARN (argparse ``type``)."""
    if not _ROLE_ARN.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not an IAM role ARN")
    return value


def encode_credentials(
    secret_arn: str,
    policy: str | None = None,
    federation_role_path: str = DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
    session_name: str = DEFAULT_SESSION_NAME,
    caller_role_arn: str | None = None,
) -> str:
    """Assume role with scoped-down session policy and encode credentials for the proxy.

    Args:
        secret_arn: The ARN of the secret in AWS Secrets Manager.
        policy: Optional IAM session policy JSON string. If None, uses the
            default policy (secretsmanager:GetSecretValue and
            sts:AssumeRole/sts:TagSession on the federation roles under
            ``federation_role_path``).
        federation_role_path: IAM path of the federation roles the default
            policy allows assuming.
        session_name: ``RoleSessionName`` for assuming the caller's own role.
        caller_role_arn: Role to assume instead of the caller's own. The
            default is rebuilt from the session ARN, which has no IAM path, so
            pass this for a caller role with a path.

    Returns:
        Base64-encoded payload suitable for the Authorization header.
    """
    sts = boto3.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role_arn = caller_role_arn or get_role_arn(caller_arn)
    account_id, _ = extract_arn_parts(caller_arn)

    policy_json = (
        policy
        if policy is not None
        else _build_default_policy(secret_arn, account_id, federation_role_path)
    )

    credentials = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        Policy=policy_json,
        DurationSeconds=TEMP_CRED_DURATION_SECONDS,
    )["Credentials"]

    return encode_payload(credentials, secret_arn)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate proxy authentication payloads",
    )
    subparsers = parser.add_subparsers(dest="command")

    encode_cmd = subparsers.add_parser(
        "encode-credentials",
        help="Encode AWS credentials for proxy authentication",
    )
    encode_cmd.add_argument(
        "secret_arn",
        help="AWS Secrets Manager ARN (e.g. arn:aws:secretsmanager:...)",
    )
    encode_cmd.add_argument(
        "--policy",
        help="Custom IAM session policy: path to a JSON file or inline JSON string.",
    )
    encode_cmd.add_argument(
        "--federation-role-path",
        default=DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
        help=(
            "IAM path of the federation roles the default policy may assume "
            f"(default: {DEFAULT_FEDERATION_ROLE_PATH_PREFIX})"
        ),
    )
    encode_cmd.add_argument(
        "--session-name",
        type=_session_name,
        default=DEFAULT_SESSION_NAME,
        help=(
            "Role session name used to assume the caller's own role; the role's "
            "trust policy may require a specific one "
            f"(default: {DEFAULT_SESSION_NAME})"
        ),
    )
    encode_cmd.add_argument(
        "--caller-role-arn",
        type=_role_arn,
        help=(
            "Role to assume instead of the caller's own role, which is rebuilt "
            "from the session ARN and so loses any IAM path"
        ),
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "encode-credentials":
        policy_json = None
        if args.policy:
            policy_json = _load_policy(args.policy)
        print(
            encode_credentials(
                args.secret_arn,
                policy=policy_json,
                federation_role_path=args.federation_role_path,
                session_name=args.session_name,
                caller_role_arn=args.caller_role_arn,
            )
        )


if __name__ == "__main__":
    main()
