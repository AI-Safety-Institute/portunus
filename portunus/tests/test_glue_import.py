"""
Regression test to verify portunus.models can be imported in AWS Glue environment.

This test ensures that lazy loading of non-standard imports (like pydantic) works
correctly, allowing JoinedLogRecord and other dataclasses to be imported in
AWS Glue jobs where pydantic is not available.

The Glue job imports the module from a zip on PYTHONPATH, so the test does the
same, on an interpreter with nothing but the standard library installed. That is
the whole invariant; it does not need the 5 GB Glue image, whose pull from ECR
Public was rate limited on most CI runs.
"""

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

# AWS Glue 5.0 runs Python 3.11: https://docs.aws.amazon.com/glue/latest/dg/release-notes.html
GLUE_PYTHON = "3.11"

GLUE_IMPORT_SCRIPT = """
import sys

# Verify pydantic is not available, as in the Glue environment
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
print(f"✓ Python {sys.version.split()[0]}")
"""


def test_glue_import_without_pydantic():
    """Test JoinedLogRecord import from a zip, on Glue's Python, without pydantic."""
    uv = shutil.which("uv")
    assert uv, "uv is required to provide a bare Python interpreter"

    models_path = Path(__file__).parent.parent / "portunus" / "models.py"
    assert models_path.exists(), f"models.py not found at {models_path}"

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Zip with the same structure as the one shipped to AWS Glue
        zip_path = temp_path / "portunus_models.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(
                "portunus/__init__.py", '"""Portunus models package for Glue jobs."""\n'
            )
            zf.write(models_path, "portunus/models.py")

        test_script = temp_path / "test_import.py"
        test_script.write_text(GLUE_IMPORT_SCRIPT)

        # --no-project gives an environment with only the standard library;
        # uv downloads the interpreter if it is not installed.
        result = subprocess.run(
            [
                uv,
                "run",
                "--no-project",
                "--python",
                GLUE_PYTHON,
                "python",
                str(test_script),
            ],
            env={**os.environ, "PYTHONPATH": str(zip_path)},
            cwd=temp_path,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

        if result.stdout:
            print("STDOUT:", result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        assert result.returncode == 0, (
            f"Glue import test failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )
        assert "✓ pydantic is not available" in result.stdout
        assert "✓ Successfully imported JoinedLogRecord" in result.stdout
        assert f"✓ Python {GLUE_PYTHON}." in result.stdout
