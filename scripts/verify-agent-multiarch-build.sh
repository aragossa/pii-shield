#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile.agent \
  .
