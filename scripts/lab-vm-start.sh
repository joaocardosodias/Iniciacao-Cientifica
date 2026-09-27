#!/usr/bin/env bash
set -euo pipefail

exec python3 "$(dirname "$0")/lab_vm.py" start "$@"
