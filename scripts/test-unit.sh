#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "Running all unit tests..."
go test -v $(go list ./... | grep -v cmd/wasm)

echo "All unit tests passed!"
