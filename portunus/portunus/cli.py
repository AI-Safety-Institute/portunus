"""Portunus CLI: proxy authentication payloads and auth-cache administration."""

import argparse
import asyncio
import json
import os
import re
import sys

import boto3

from portunus.config import DEFAULT_FEDERATION_ROLE_PATH_PREFIX, config
from portunus.services.arn_service import extract_arn_parts, get_role_arn
from portunus.services.payload_service import encode_payload

TEMP_CRED_DURATION_SECONDS = 12 * 60 * 60
DEFAULT_SESSION_NAME = "portunus"
# STS's RoleSessionName rule; the charset is ASCII, so re.ASCII keeps \w from
# admitting more.
_ROLE_SESSION_NAME = re.compile(r"^[\w+=,.@-]{2,64}$", re.ASCII)


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


def encode_credentials(
    secret_arn: str,
    policy: str | None = None,
    federation_role_path: str = DEFAULT_FEDERATION_ROLE_PATH_PREFIX,
    session_name: str = DEFAULT_SESSION_NAME,
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
        RoleSessionName=session_name,
        Policy=policy_json,
        DurationSeconds=TEMP_CRED_DURATION_SECONDS,
    )["Credentials"]

    return encode_payload(credentials, secret_arn)


def flush_auth_cache(assume_yes: bool = False) -> int:
    """Flush the shared auth cache (Redis ``FLUSHDB``) after confirmation.

    Prints the Redis target (never the password) before flushing, and asks
    for confirmation unless ``assume_yes``.

    Args:
        assume_yes: Skip the confirmation prompt (``--yes``).

    Returns:
        The process exit code: 0 when flushed, 1 when the flush was not
        confirmed or Redis is unavailable.
    """
    from portunus.services.cache_service import CacheService

    redis = config.redis
    print(
        f"About to flush the Portunus auth cache: FLUSHDB on Redis "
        f"{redis.host}:{redis.port}, database 0 "
        f"(TLS {'on' if redis.use_tls else 'off'})."
    )
    print(
        "This deletes every key in that database, including keys of any other "
        "application sharing it."
    )
    if not assume_yes:
        answer = input("Type 'yes' to flush: ")
        if answer.strip().lower() != "yes":
            print("Not confirmed; nothing was flushed.", file=sys.stderr)
            return 1

    async def _flush() -> bool:
        cache = CacheService()
        try:
            return await cache.flush_all()
        finally:
            await cache.state_service.close_redis_client()

    try:
        flushed = asyncio.run(_flush())
    except Exception as e:
        print(f"Flush failed: {e}", file=sys.stderr)
        return 1
    if not flushed:
        print("Flush failed: Redis unavailable.", file=sys.stderr)
        return 1
    print("Auth cache flushed.")
    return 0


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate proxy authentication payloads and administer "
        "the auth cache",
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

    flush_cmd = subparsers.add_parser(
        "flush-auth-cache",
        help="Delete every cached auth result in the configured Redis (FLUSHDB)",
    )
    flush_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Flush without asking for confirmation",
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
            )
        )
    elif args.command == "flush-auth-cache":
        sys.exit(flush_auth_cache(assume_yes=args.yes))


if __name__ == "__main__":
    main()
