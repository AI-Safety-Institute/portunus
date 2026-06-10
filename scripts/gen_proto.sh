#!/usr/bin/env bash
# Regenerate the Python protobuf/gRPC stubs from proto/ into
# portunus/portunus/grpc/_generated/.
#
# Uses grpcio-tools' bundled protoc (no external binaries, no Buf Schema
# Registry / network dependency), so it runs identically offline and in CI.
# Buf is still used for `buf lint` (also local). Commit the regenerated stubs;
# the pre-commit / CI freshness check (`gen_proto.sh && git diff --exit-code`)
# fails if they drift from proto/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
OUT_DIR="$REPO_ROOT/portunus/portunus/grpc/_generated"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Run from the portunus/ project so grpcio-tools resolves in that venv.
cd "$REPO_ROOT/portunus"
uv run python -m grpc_tools.protoc \
  --proto_path="$PROTO_DIR" \
  --python_out="$OUT_DIR" \
  --pyi_out="$OUT_DIR" \
  --grpc_python_out="$OUT_DIR" \
  "$PROTO_DIR"/portunus_admin/v1/admin.proto

echo "Generated stubs in $OUT_DIR"
