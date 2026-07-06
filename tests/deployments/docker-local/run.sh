#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir docker-local)"
image="${IMAGE:-pii-shield:manual}"
trap 'cleanup_docker_images "${image}"' EXIT
enable_runtime_metrics_by_default
prepare_pii_env_args

docker build -t "${image}" "${repo_root}"
print_runtime_metrics_hint
docker run -i --rm \
  "${pii_docker_port_args[@]}" \
  "${pii_docker_env_args[@]}" \
  "${image}" \
  < "${fixture}" \
  > "${output_dir}/access.sanitized.log"

assert_sanitized_file "${output_dir}/access.sanitized.log"
