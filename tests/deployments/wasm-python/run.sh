#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir wasm-python)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="${PII_PY_IMAGE:-python:3.11-slim}"
prepare_pii_env_args

# Run the Python SDK inside a Linux container. The wasmtime runtime the SDK uses is
# SIGKILLed (`Killed: 9`) ~2s after loading the WASM module on macOS — a wasmtime-on-macOS
# problem, not a pii-shield bug (the identical .wasm runs fine under Node on macOS and
# under wasmtime on Linux; see README.md). Running in a container makes the test
# host-OS-independent. Mounts: the fixture (read-only), the redaction script (read-only),
# and the output dir so the sanitized log lands on the host.
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required: this test runs the Python SDK inside a Linux container (wasmtime is killed on macOS). See README.md." >&2
  exit 1
fi

docker run --rm \
  ${pii_docker_env_args[@]+"${pii_docker_env_args[@]}"} \
  -v "${fixture}":/fixture:ro \
  -v "${script_dir}/redact.py":/redact.py:ro \
  -v "${output_dir}":/out \
  "${image}" \
  bash -c "pip install -q pii-shield-wasi && python /redact.py /fixture /out/access.sanitized.log"

assert_sanitized_file "${output_dir}/access.sanitized.log"
