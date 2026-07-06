#!/usr/bin/env bash
# Run every test tier in order: unit -> operator integration -> smoke ->
# deployment matrix. An optional argument selects the deployment group
# (default: all); see scripts/test-deployments.sh for the groups.
#
# Usage: scripts/test-all.sh [deployment-group]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== 1/4 unit tests ==="
"${ROOT_DIR}/scripts/test-unit.sh"

echo "=== 2/4 operator integration tests (envtest) ==="
"${ROOT_DIR}/scripts/test-operator-integration.sh"

echo "=== 3/4 smoke tests ==="
"${ROOT_DIR}/scripts/test-smoke.sh"

echo "=== 4/4 deployment matrix ==="
"${ROOT_DIR}/scripts/test-deployments.sh" "${1:-all}"
