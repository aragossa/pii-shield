#!/bin/bash
set -e

echo "Running all unit tests..."
go test -v ./...
