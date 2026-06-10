#!/usr/bin/env bash
# Regenerate the Python protobuf/gRPC stubs from proto/ as real submodules of
# the ``portunus`` package (portunus/portunus/admin/v1/).
#
# The proto package is ``portunus.admin.v1`` so the generated modules are
# ordinary submodules of the installed ``portunus`` package — they import each
# other by absolute import (``from portunus.admin.v1 import admin_pb2``) with NO
# sys.path manipulation and no import-order coupling.
#
# Uses grpcio-tools' bundled protoc (no external binaries, no Buf Schema
# Registry / network dependency) so it runs identically offline and in CI.
# Buf is still used for ``buf lint``. Commit the regenerated stubs; the
# pre-commit / CI freshness check (`gen_proto.sh && git diff --exit-code`) fails
# if they drift from proto/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
# protoc writes <out>/<proto-package-path>/..., e.g. <out>/portunus/admin/v1/.
# So point <out> at the project dir; the stubs land inside the package at
# portunus/portunus/admin/v1/.
PROJECT_DIR="$REPO_ROOT/portunus"
PKG_ADMIN_DIR="$PROJECT_DIR/portunus/admin"

# Wipe only the generated admin subpackage (not the whole package).
rm -rf "$PKG_ADMIN_DIR"

cd "$PROJECT_DIR"
uv run python -m grpc_tools.protoc \
  --proto_path="$PROTO_DIR" \
  --python_out="$PROJECT_DIR" \
  --pyi_out="$PROJECT_DIR" \
  --grpc_python_out="$PROJECT_DIR" \
  "$PROTO_DIR"/portunus/admin/v1/admin.proto

# protoc doesn't emit package __init__.py files; ``portunus`` is a regular
# (non-namespace) package, so the new subpackages need them to be importable.
touch "$PKG_ADMIN_DIR/__init__.py" "$PKG_ADMIN_DIR/v1/__init__.py"

echo "Generated stubs in $PKG_ADMIN_DIR"
