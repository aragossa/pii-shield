#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
cleanup_operator_replay
(
  cd "${repo_root}/operator"
  make undeploy ignore-not-found=true
  make uninstall ignore-not-found=true
)
