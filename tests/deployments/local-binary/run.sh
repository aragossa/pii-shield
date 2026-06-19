#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir local-binary)"
enable_runtime_metrics_by_default
prepare_pii_env_args

mkdir -p "${repo_root}/bin"
go build -o "${repo_root}/bin/pii-shield" "${repo_root}/cmd/cleaner/main.go"

print_runtime_metrics_hint
env "${pii_process_env_args[@]}" \
  "${repo_root}/bin/pii-shield" \
  < "${fixture}" \
  > "${output_dir}/access.sanitized.log"

assert_sanitized_file "${output_dir}/access.sanitized.log"
