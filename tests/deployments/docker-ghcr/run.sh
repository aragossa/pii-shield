#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir docker-ghcr)"
image="${IMAGE:-ghcr.io/pii-shield/pii-shield:2.1.0}"
enable_runtime_metrics_by_default
prepare_pii_env_args

docker pull "${image}"
print_runtime_metrics_hint
docker run -i --rm \
  "${pii_docker_port_args[@]}" \
  "${pii_docker_env_args[@]}" \
  "${image}" \
  < "${fixture}" \
  > "${output_dir}/access.sanitized.log"

assert_sanitized_file "${output_dir}/access.sanitized.log"
