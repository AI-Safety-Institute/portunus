"""Shared pytest fixtures for API Key Proxy tests."""

import json
import os
import subprocess
import sys
import time
from base64 import b64encode
from datetime import datetime
from pathlib import Path

import pytest
import yaml

# Add portunus to the Python path
portunus_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "portunus")
if portunus_path not in sys.path:
    sys.path.append(portunus_path)

# Disable X-Ray SDK for tests
os.environ["AWS_XRAY_SDK_ENABLED"] = "false"

# Set default region for tests (config validation requires it)
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call
    setattr(item, f"rep_{rep.when}", rep)


@pytest.fixture(autouse=True)
def _dump_container_logs_on_failure(request):
    """Dump the most-relevant container tails to stderr when a test fails.

    Auth/relay debugging relies on the portunus + proxy logs that disappear
    once docker-compose tears down. We capture them here on failure so CI
    output is actionable without having to re-run with a custom command.
    """
    yield
    if not os.environ.get("DUMP_DOCKER_LOGS_ON_FAILURE"):
        return
    rep = getattr(request.node, "rep_call", None)
    if rep is None or not rep.failed:
        return
    for name in ("portunus", "portunus-proxy-1", "localstack-main"):
        result = subprocess.run(
            ["docker", "logs", "--tail=120", name],
            capture_output=True,
            text=True,
        )
        sys.stderr.write(
            f"\n=== {name} logs (tail 120) ===\n{result.stdout}\n{result.stderr}\n"
        )


# Load the compose file once for all tests
with open("docker-compose.yaml", "r") as f:
    COMPOSE_FILE = yaml.safe_load(f)

# Expected API key value that LocalStack will return from test-api-key secret
# This matches what's configured in docker-compose.yaml localstack post_start
DEFAULT_LOCAL_API_KEY = "xyz"

# Set custom header prefix to test configurability (doubles as backwards-compat check)
COMPOSE_FILE["services"]["proxy"]["environment"]["PORTUNUS_HEADER_PREFIX"] = (
    "aisi-proxy"
)

# Redis setup for testing
COMPOSE_FILE["services"]["portunus"]["environment"]["REDIS_HOST"] = "redis"
COMPOSE_FILE["services"]["portunus"]["environment"]["REDIS_PORT"] = "6379"
COMPOSE_FILE["services"]["portunus"]["environment"]["CACHE_DURATION"] = "3600"
COMPOSE_FILE["services"]["portunus"]["environment"]["REDIS_PASSWORD"] = (
    "redis_secure_password"
)


@pytest.fixture(scope="session")
def compose_file():
    """Return the compose file configuration."""
    return COMPOSE_FILE


@pytest.fixture(scope="session")
def docker_setup(request, compose_file):
    """Set up and tear down Docker containers for tests.

    The default test-api-key secret is created by docker-compose.yaml.
    Can be parameterized with a custom secret value for test-api-key.
    Returns the configured API key value.
    """
    # Get custom secret value if parameterized
    custom_secret_value = getattr(request, "param", None)

    compose_config = compose_file.copy()
    # Ensure logs directory exists and is clean
    logs_dir = Path("./logs")
    if logs_dir.exists():
        # Clean up any existing log files
        for log_file in logs_dir.glob("*.jsonl"):
            log_file.unlink()
    else:
        logs_dir.mkdir(exist_ok=True)

    # Add debug logs directory for capturing container logs during tests
    debug_logs_dir = Path("./debug_logs")
    if not debug_logs_dir.exists():
        debug_logs_dir.mkdir(exist_ok=True)

    # Set up Redis environment variables
    setup_redis_env(compose_config)

    # Start the Docker Compose file
    result = subprocess.run(
        ["docker", "compose", "-f", "-", "up", "-d", "--build", "--wait"],
        input=yaml.dump(compose_config).encode(),
        capture_output=True,
    )

    # Wait a bit longer for the containers to be fully ready
    time.sleep(5)  # Add extra time for services to initialize

    if result.returncode != 0:
        # Dump localstack logs for debugging before failing
        if os.environ.get("DUMP_DOCKER_LOGS_ON_FAILURE"):
            import sys as _sys

            for name in ["localstack-main", "portunus", "portunus-proxy-1"]:
                logs = subprocess.run(
                    ["docker", "logs", "--tail=80", name],
                    capture_output=True,
                    text=True,
                )
                _sys.stderr.write(
                    f"\n=== {name} logs ===\n{logs.stdout}\n{logs.stderr}\n"
                )
        pytest.fail(f"Failed to start Docker containers: {result.stderr}")  # type: ignore[invalid-argument-type]

    # If a custom secret value was specified, update it in LocalStack
    if custom_secret_value:
        create_localstack_secret("test-api-key", custom_secret_value)
        yield custom_secret_value
    else:
        yield DEFAULT_LOCAL_API_KEY

    # Stop the Docker Compose file
    subprocess.run(["docker", "compose", "down"])


@pytest.fixture
def api_key_prefix(compose_file):
    """Return the API key prefix from the compose file."""
    return compose_file["services"]["proxy"]["environment"]["API_KEY_PREFIX"]


@pytest.fixture
def api_key_header(compose_file):
    """Return the API key header from the compose file."""
    return compose_file["services"]["proxy"]["environment"]["API_KEY_HEADER"]


def encode_base64(data: dict, secret_name: str = "test-api-key") -> str:
    """Encode a dictionary as base64 JSON string.

    Args:
        data: Dictionary containing credentials and secret_arn
        secret_name: Name of the secret in LocalStack (default: test-api-key)
    """
    # If credentials are empty, add LocalStack test credentials
    if "credentials" in data and not data["credentials"]:
        data["credentials"] = {
            "access_key_id": "000000000000",
            "secret_access_key": "test",
            "session_token": "test",
        }

    # If secret_arn is empty, add the LocalStack test secret ARN
    if "secret_arn" in data and not data["secret_arn"]:
        data["secret_arn"] = (
            f"arn:aws:secretsmanager:eu-west-2:000000000000:secret:{secret_name}"
        )

    return b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")


def create_localstack_secret(secret_name: str, secret_value: str) -> None:
    """Create or update a secret in LocalStack Secrets Manager.

    Args:
        secret_name: Name of the secret to create
        secret_value: Value to store in the secret
    """
    # Try to create the secret, if it exists, update it
    result = subprocess.run(
        [
            "docker",
            "exec",
            "localstack-main",
            "awslocal",
            "secretsmanager",
            "create-secret",
            "--name",
            secret_name,
            "--secret-string",
            secret_value,
            "--region",
            "eu-west-2",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0 and "ResourceExistsException" in result.stderr:
        # Secret exists, update it instead
        subprocess.run(
            [
                "docker",
                "exec",
                "localstack-main",
                "awslocal",
                "secretsmanager",
                "update-secret",
                "--secret-id",
                secret_name,
                "--secret-string",
                secret_value,
                "--region",
                "eu-west-2",
            ],
            capture_output=True,
            check=True,
        )


# Set up Redis environment variables for portunus
def setup_redis_env(compose_file):
    """Set up Redis environment variables from compose file."""
    redis_host = "localhost"
    redis_port = 6379  # The standard port mapping in docker-compose
    redis_password = compose_file["services"]["portunus"]["environment"][
        "REDIS_PASSWORD"
    ]

    # Set environment variables to match the docker-compose setup
    os.environ["REDIS_HOST"] = redis_host
    os.environ["REDIS_PORT"] = str(redis_port)
    os.environ["REDIS_PASSWORD"] = redis_password


def dump_container_logs(test_name="unknown"):
    """Extract logs from all running containers to debug_logs directory."""
    debug_logs_dir = Path("./debug_logs")
    if not debug_logs_dir.exists():
        debug_logs_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Get list of running containers
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True,
        )

        containers = result.stdout.strip().split("\n")
        for container in containers:
            if not container:
                continue

            log_file = debug_logs_dir / f"{container}_{test_name}_{timestamp}.log"
            print(f"Extracting logs from {container} to {log_file}")

            with open(log_file, "w") as f:
                subprocess.run(
                    ["docker", "logs", container],
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

        print(f"Logs saved to {debug_logs_dir}")
    except Exception as e:
        print(f"Failed to dump container logs: {e}")
