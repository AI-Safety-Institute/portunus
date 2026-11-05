"""The image HEALTHCHECK probes the port(s) the container's GRPC_ROLE serves."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

_PORTUNUS_DIR = Path(__file__).resolve().parents[1]
_SCRIPT = _PORTUNUS_DIR / "healthcheck.sh"


def _run(tmp_path: Path, env: dict[str, str], *, failing_ports=()) -> tuple[int, list]:
    """Run the real script with a fake grpc_health_probe that logs its target."""
    log = tmp_path / "probes.log"
    fake = tmp_path / "grpc_health_probe"
    failing = " ".join(f"-addr=127.0.0.1:{p}" for p in failing_ports)
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {log}\n'
        f'for bad in {failing}; do [ "$1" = "$bad" ] && exit 2; done\n'
        "exit 0\n"
    )
    fake.chmod(0o755)
    result = subprocess.run(
        ["sh", str(_SCRIPT)],
        env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "GRPC_PORT": "9000", **env},
        capture_output=True,
        text=True,
        timeout=10,
    )
    probes = log.read_text().split() if log.exists() else []
    return result.returncode, probes


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, ["-addr=127.0.0.1:9000"]),
        ({"GRPC_ROLE": "all"}, ["-addr=127.0.0.1:9000"]),
        (
            {"GRPC_ROLE": "all", "GRPC_AUDIT_PORT": "9001"},
            ["-addr=127.0.0.1:9000", "-addr=127.0.0.1:9001"],
        ),
        ({"GRPC_ROLE": "auth", "GRPC_AUDIT_PORT": "9001"}, ["-addr=127.0.0.1:9000"]),
        ({"GRPC_ROLE": "audit", "GRPC_AUDIT_PORT": "9001"}, ["-addr=127.0.0.1:9001"]),
        # An audit-only process without GRPC_AUDIT_PORT listens on GRPC_PORT.
        ({"GRPC_ROLE": "audit"}, ["-addr=127.0.0.1:9000"]),
    ],
)
def test_probe_targets_the_ports_the_role_serves(tmp_path, env, expected):
    code, probes = _run(tmp_path, env)
    assert code == 0
    assert probes == expected


@pytest.mark.parametrize(
    ("env", "failing"),
    [
        ({"GRPC_ROLE": "audit", "GRPC_AUDIT_PORT": "9001"}, "9001"),
        ({"GRPC_ROLE": "all", "GRPC_AUDIT_PORT": "9001"}, "9000"),
        ({"GRPC_ROLE": "all", "GRPC_AUDIT_PORT": "9001"}, "9001"),
        ({"GRPC_ROLE": "auth"}, "9000"),
    ],
)
def test_any_unhealthy_served_port_fails_the_probe(tmp_path, env, failing):
    code, _ = _run(tmp_path, env, failing_ports=(failing,))
    assert code != 0


def test_image_healthcheck_runs_the_script():
    dockerfile = (_PORTUNUS_DIR / "Dockerfile").read_text()
    copy = re.search(r"^COPY .*healthcheck\.sh (\S+)$", dockerfile, re.MULTILINE)
    assert copy is not None
    installed = Path(copy.group(1)).name
    healthcheck = re.search(
        r"^HEALTHCHECK [^\n]*\\\n\s+CMD (.+)$", dockerfile, re.MULTILINE
    )
    assert healthcheck is not None
    assert healthcheck.group(1).split()[0] == installed
