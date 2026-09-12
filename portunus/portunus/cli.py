"""Portunus CLI for generating proxy authentication payloads."""

import argparse
import json
import os
import sys

import boto3

from portunus.config import DEFAULT_FEDERATION_ROLE_PATH_PREFIX
from portunus.services.arn_service import extract_arn_parts, get_role_arn
from portunus.services.payload_service import encode_payload

TEMP_CRED_DURATION_SECONDS = 12 * 60 * 60

DEFAULT_POLICY_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SecretsManagerAccess",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "{secret_arn}",
        },
        {
            "Sid": "KMSSignAccess",
            "Effect": "Allow",
            "Action": ["kms:Sign"],
            "Resource": "*",
        },
        {
            "Sid": "FederationRoleAccess",
            "Effect": "Allow",
            "Action": ["sts:AssumeRole"],
            "Resource": "{federation_role_arn_pattern}",
        },
    ],
}


def _build_default_policy(
    secret_arn: str,
    account_id: str,
    federation_role_path: str = DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
) -> str:
    """Build the default session policy for one secret.

    Grants GetSecretValue on ``secret_arn``, kms:Sign, and sts:AssumeRole on
    the federation roles under ``federation_role_path`` in the caller's
    account (needed when the secret mints a token rather than storing one).
    """
    policy = json.loads(json.dumps(DEFAULT_POLICY_TEMPLATE))
    policy["Statement"][0]["Resource"] = secret_arn
    policy["Statement"][2]["Resource"] = (
        f"arn:aws:iam::{account_id}:role{federation_role_path}*"
    )
    return json.dumps(policy)


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


def encode_credentials(
    secret_arn: str,
    policy: str | None = None,
    federation_role_path: str = DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
) -> str:
    """Assume role with scoped-down session policy and encode credentials for the proxy.

    Args:
        secret_arn: The ARN of the secret in AWS Secrets Manager.
        policy: Optional IAM session policy JSON string. If None, uses the
            default policy (secretsmanager:GetSecretValue, kms:Sign, and
            sts:AssumeRole on the caller account's federation roles).
        federation_role_path: IAM path of the federation roles the default
            policy allows assuming.

    Returns:
        Base64-encoded payload suitable for the Authorization header.
    """
    sts = boto3.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role_arn = get_role_arn(caller_arn)
    account_id, _ = extract_arn_parts(caller_arn)

    policy_json = (
        policy
        if policy is not None
        else _build_default_policy(secret_arn, account_id, federation_role_path)
    )

    credentials = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="portunus",
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
            )
        )


if __name__ == "__main__":
    main()
