#!/usr/bin/env bash
# List non-admin users and last login time.
# Usage (from repo root):
#   ./tools/list-students.sh
#   ./tools/list-students.sh --json
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec node tools/list-students.js "$@"
