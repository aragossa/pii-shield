#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
image_tag="${IMAGE_TAG:-manual-$(date +%Y%m%d%H%M%S)}"
operator_image="ghcr.io/pii-shield/pii-shield-operator:${image_tag}"
agent_image="ghcr.io/pii-shield/pii-shield-agent:${image_tag}"

# Make sure a local kind cluster exists before we load images and deploy into it
# (recreate it if it was deleted), so the steps below have somewhere to run.
ensure_local_cluster

(
  cd "${repo_root}/operator"
  make docker-build IMG="${operator_image}"
)
docker build -t "${agent_image}" -f "${repo_root}/Dockerfile.agent" "${repo_root}"

load_image_into_current_local_cluster "${operator_image}"
load_image_into_current_local_cluster "${agent_image}"

IMAGE_TAG="${image_tag}" "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chart.sh" upgrade

kubectl rollout status deployment/pii-shield-operator -n operator-system --timeout=120s

build_replay_image "${repo_root}"
load_replay_image
deploy_operator_replay_pods
collect_operator_replay_logs "operator-local-images"
