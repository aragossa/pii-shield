#!/bin/bash
set -e

echo "Running all unit tests..."
go test -v $(go list ./... | grep -v cmd/wasm)

echo "All unit tests passed!"
