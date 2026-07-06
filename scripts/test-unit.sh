#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "Running root module unit tests..."
go test -v $(go list ./... | grep -v cmd/wasm)

echo "Running operator unit tests..."
(cd "${ROOT_DIR}/operator" && go test ./api/... ./internal/...)

echo "All unit tests passed!"
