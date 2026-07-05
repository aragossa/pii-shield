#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPERATOR_DIR="${ROOT_DIR}/operator"

if [ ! -d "${OPERATOR_DIR}" ]; then
  echo "operator directory not found at ${OPERATOR_DIR}" >&2
  exit 1
fi

export GOCACHE="${GOCACHE:-${ROOT_DIR}/.gocache}"

echo "Running operator integration tests with envtest..."
echo "Note: these tests start a local Kubernetes API server and require localhost bind permissions."

cd "${OPERATOR_DIR}"
go test -tags=integration ./internal/controller/...
