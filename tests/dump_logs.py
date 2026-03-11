#!/usr/bin/env python
"""
Utility script to extract logs from Docker containers for debugging.

Run this script after a test failure to get logs from all containers.
"""

import subprocess
from datetime import datetime
from pathlib import Path


def dump_container_logs():
    """Extract logs from all running containers to debug_logs directory."""
    debug_logs_dir = Path("./debug_logs")
    if not debug_logs_dir.exists():
        debug_logs_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Get list of running containers
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

        log_file = debug_logs_dir / f"{container}_{timestamp}.log"
        print(f"Extracting logs from {container} to {log_file}")

        with open(log_file, "w") as f:
            subprocess.run(
                ["docker", "logs", container],
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
            )

    print(f"Logs saved to {debug_logs_dir}")


if __name__ == "__main__":
    dump_container_logs()
