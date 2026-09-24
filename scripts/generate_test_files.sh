#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/tools/generate_test_files/Cargo.toml"
BIN="$ROOT/target/release/generate_test_files"
cargo build --release --manifest-path "$MANIFEST" >/dev/null
exec "$BIN" "$@"
