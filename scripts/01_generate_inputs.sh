#!/usr/bin/env bash
# Step 2 (Section 5.2 of documentation/context.pdf):
# Declarative, config-driven deterministic input vector generation.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONFIG_FILE="${CONFIG_FILE:-config/benchmark_matrix.json}"
OUT_DIR="${OUT_DIR:-data}"
SUITE="${SUITE:-all}"

echo "=== [Step 01] Generating deterministic input vectors (config=${CONFIG_FILE}, suite=${SUITE}) ==="
cargo run --release -p input-generator -- --config "$CONFIG_FILE" --suite "$SUITE" --out-dir "$OUT_DIR" "$@"
cargo run --release -p input-generator -- --config "$CONFIG_FILE" --verify --out-dir "$OUT_DIR"
echo "=== [Step 01] Input generation & self-verification complete ==="
