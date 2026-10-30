"""Every third-party module the service imports is installed in the image.

The image installs runtime dependencies only (``uv sync --frozen --no-dev``),
while tests run with the dev group too, so a module that only a dev dependency
pulls in imports fine here and crashes the container at startup. This test
closes that gap without building the image: each third-party import under
``portunus/`` must belong to a runtime dependency or to something a runtime
dependency requires.
"""

import ast
import re
import sys
import tomllib
from importlib.metadata import (
    PackageNotFoundError,
    distribution,
    packages_distributions,
)
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    assert match, requirement
    return _canonical(match.group(1))


def _runtime_closure() -> set[str]:
    """Runtime dependencies and everything they require, as installed."""
    pyproject = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())
    pending = [_requirement_name(r) for r in pyproject["project"]["dependencies"]]
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        try:
            requires = distribution(name).requires or []
        except PackageNotFoundError:
            continue
        for requirement in requires:
            if "extra ==" in requirement:
                continue
            pending.append(_requirement_name(requirement))
    return seen


def _third_party_imports() -> set[str]:
    modules: set[str] = set()
    for path in (PACKAGE_ROOT / "portunus").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                modules.add(node.module.split(".")[0])
    return {
        module
        for module in modules
        if module not in sys.stdlib_module_names and module != "portunus"
    }


def test_every_imported_module_ships_with_the_runtime_dependencies():
    providers = packages_distributions()
    runtime = _runtime_closure()

    unshipped = {
        module: sorted(providers.get(module, ["<not installed>"]))
        for module in _third_party_imports()
        if not any(_canonical(dist) in runtime for dist in providers.get(module, []))
    }

    assert not unshipped, (
        "imported by portunus/ but not provided by a runtime dependency "
        f"(add to [project].dependencies): {unshipped}"
    )
