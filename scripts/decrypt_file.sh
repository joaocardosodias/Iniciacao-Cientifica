#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/tools/decrypt_file/Cargo.toml"
BIN="$ROOT/target/release/decrypt_file"
cargo build --release --manifest-path "$MANIFEST" >/dev/null
exec "$BIN" "$@"
