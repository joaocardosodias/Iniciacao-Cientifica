#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/tools/reset_vm/Cargo.toml"
BIN="$ROOT/target/release/reset_vm"
cargo build --release --manifest-path "$MANIFEST" >/dev/null
exec "$BIN" --root "$ROOT" "$@"
