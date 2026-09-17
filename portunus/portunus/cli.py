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
_IAM_WILDCARDS = re.compile(r"[*?]")


def _federation_role_pattern(
    secret_arn: str, account_id: str, federation_role_path: str
) -> str | None:
    """The federation roles a payload for ``secret_arn`` may assume.

    Federation roles sit at ``role<federation_role_path><namespace>/<name>``
    and secrets are named ``<namespace>/<name>``, ``<namespace>`` being two
    path segments, so the first two segments of the secret's name select the
    roles in its namespace. The last segment (the secret's own name plus
    Secrets Manager's random suffix) plays no part.

    Returns None when the name has fewer than two leading path segments; the
    default policy then grants no sts:AssumeRole.

    Raises:
        ValueError: A namespace segment contains ``*`` or ``?``, which are
            wildcards in an IAM resource ARN and would widen the grant.
    """
    _, _, name = secret_arn.partition(":secret:")
    segments = name.split("/")
    if len(segments) < 3 or not (segments[0] and segments[1]):
        return None
    for segment in segments[:2]:
        if _IAM_WILDCARDS.search(segment):
            raise ValueError(
                f"secret name segment {segment!r} contains an IAM wildcard character"
            )
    return (
        f"arn:aws:iam::{account_id}:role{federation_role_path}"
        f"{segments[0]}/{segments[1]}/*"
    )


def _build_default_policy(
    secret_arn: str,
    account_id: str,
    federation_role_path: str = DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
) -> str:
    """Build the default session policy for one secret.

    Grants GetSecretValue on ``secret_arn``, kms:Sign, and (when the secret's
    name places it in a namespace) sts:AssumeRole on the federation roles of
    that namespace under ``federation_role_path`` in the caller's account.
    """
    statements: list[dict[str, object]] = [
        {
            "Sid": "SecretsManagerAccess",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": secret_arn,
        },
        {
            "Sid": "KMSSignAccess",
            "Effect": "Allow",
            "Action": ["kms:Sign"],
            "Resource": "*",
        },
    ]
    role_pattern = _federation_role_pattern(
        secret_arn, account_id, federation_role_path
    )
    if role_pattern is not None:
        statements.append(
            {
                "Sid": "PortunusFederationAssumeRole",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"],
                "Resource": role_pattern,
            }
        )
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
            sts:AssumeRole on the federation roles in the secret's namespace).
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
