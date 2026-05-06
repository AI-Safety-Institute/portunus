"""
Regression test to verify portunus.models can be imported in AWS Glue environment.

This test ensures that lazy loading of non-standard imports (like pydantic) works
correctly, allowing JoinedLogRecord and other dataclasses to be imported in
AWS Glue jobs where pydantic is not available.
"""

import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest


@pytest.mark.slow
def test_glue_import_without_pydantic():
    """Test JoinedLogRecord import in AWS Glue without pydantic."""
    # Get path to models.py
    models_path = Path(__file__).parent.parent / "portunus" / "models.py"
    assert models_path.exists(), f"models.py not found at {models_path}"

    # Create temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create portunus package structure (matches AWS Glue zip structure)
        portunus_dir = temp_path / "portunus"
        portunus_dir.mkdir()

        # Create __init__.py
        (portunus_dir / "__init__.py").write_text(
            '"""Portunus models package for Glue jobs."""\n'
        )

        # Copy models.py
        (portunus_dir / "models.py").write_text(models_path.read_text())

        # Create zip file with same structure as AWS Glue
        zip_path = temp_path / "portunus_models.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(portunus_dir / "__init__.py", "portunus/__init__.py")
            zf.write(portunus_dir / "models.py", "portunus/models.py")

        # Create Python test script
        test_script = temp_path / "test_import.py"
        test_script.write_text(
            """
import sys

# Verify pydantic is not available in Glue environment
try:
    import pydantic
    print("WARNING: pydantic is available (unexpected)")
except ImportError:
    print("✓ pydantic is not available (expected)")

# Test the actual import
from portunus.models import JoinedLogRecord

# Verify it's a dataclass
assert hasattr(JoinedLogRecord, '__dataclass_fields__'), "Not a dataclass"

# Test that we can access the glue_schema method
schema = JoinedLogRecord.glue_schema()
assert len(schema) > 0, "glue_schema() returned empty list"

print(f"✓ Successfully imported JoinedLogRecord with {len(schema)} schema fields")
"""
        )

        # Run the test in AWS Glue Docker container
        # Use bash to invoke Python (Glue image has custom Python setup)
        # ``isal`` is a required runtime dep of portunus.models (see
        # _decompress_b64_body). In production Glue jobs it is
        # installed via ``--additional-python-modules``; the test
        # container has to do the same to mirror the runtime
        # environment, otherwise the import fails at first-call.
        bash_cmd = (
            "pip install --quiet isal && "
            "export PYTHONPATH=/home/hadoop/workspace/portunus_models.zip && "
            "python3 /home/hadoop/workspace/test_import.py"
        )

        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{zip_path}:/home/hadoop/workspace/portunus_models.zip:ro",
            "-v",
            f"{test_script}:/home/hadoop/workspace/test_import.py:ro",
            "--entrypoint",
            "bash",
            "public.ecr.aws/glue/aws-glue-libs:5",
            "-c",
            bash_cmd,
        ]

        # Run and capture output
        # Note: First run may take several minutes to pull the ~10GB Glue image
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, check=False
        )

        # Print output for debugging
        if result.stdout:
            print("STDOUT:", result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        # Check that the test passed
        assert result.returncode == 0, (
            f"Glue import test failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

        # Verify expected output
        assert "✓ pydantic is not available" in result.stdout
        assert "✓ Successfully imported JoinedLogRecord" in result.stdout
