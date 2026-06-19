#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
operator_image="${OPERATOR_IMAGE:-controller:manual}"
agent_image="${AGENT_IMAGE:-pii-shield-agent:manual}"

require_cert_manager_crds

(
  cd "${repo_root}/operator"
  make docker-build IMG="${operator_image}"
)
docker build -t "${agent_image}" -f "${repo_root}/Dockerfile.agent" "${repo_root}"

load_image_into_current_local_cluster "${operator_image}"
load_image_into_current_local_cluster "${agent_image}"

(
  cd "${repo_root}/operator"
  make deploy IMG="${operator_image}"
)

kubectl set env deployment/operator-controller-manager -n operator-system AGENT_IMAGE="${agent_image}"
kubectl rollout status deployment/operator-controller-manager -n operator-system --timeout=120s

build_replay_image "${repo_root}"
load_replay_image
deploy_operator_replay_pods
collect_operator_replay_logs "operator-kustomize"
