#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"

# Make sure a local kind cluster exists before we install the chart into it
# (recreate it if it was deleted), so the install below has somewhere to run.
ensure_local_cluster
"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chart.sh" upgrade

kubectl rollout status deployment/pii-shield-operator -n operator-system --timeout=120s
kubectl get crd piipolicies.core.pii-shield.io

build_replay_image "${repo_root}"
load_replay_image
deploy_operator_replay_pods
collect_operator_replay_logs "operator-helm-published"
