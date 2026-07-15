"""Portunus CLI: proxy authentication payloads and operator commands."""

import argparse
import asyncio
import json
import os
import sys

import boto3

from portunus.services.arn_service import get_role_arn
from portunus.services.cache_service import CacheService
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
    ],
}


def _build_default_policy(secret_arn: str) -> str:
    """Build the default session policy scoped to a specific secret ARN."""
    policy = json.loads(json.dumps(DEFAULT_POLICY_TEMPLATE))
    policy["Statement"][0]["Resource"] = secret_arn
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


def encode_credentials(secret_arn: str, policy: str | None = None) -> str:
    """Assume role with scoped-down session policy and encode credentials for the proxy.

    Args:
        secret_arn: The ARN of the secret in AWS Secrets Manager.
        policy: Optional IAM session policy JSON string. If None, uses the
            default policy (secretsmanager:GetSecretValue + kms:Sign).

    Returns:
        Base64-encoded payload suitable for the Authorization header.
    """
    sts = boto3.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role_arn = get_role_arn(caller_arn)

    policy_json = policy if policy is not None else _build_default_policy(secret_arn)

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

    subparsers.add_parser(
        "flush-cache",
        help=(
            "Flush the shared auth cache and signal every task to drop its "
            "in-process copy (uses the task's own Redis configuration)"
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
        print(encode_credentials(args.secret_arn, policy=policy_json))
    elif args.command == "flush-cache":
        flushed = asyncio.run(CacheService().flush_all())
        print(f"flushed: {flushed}")
        sys.exit(0 if flushed else 1)


if __name__ == "__main__":
    main()
