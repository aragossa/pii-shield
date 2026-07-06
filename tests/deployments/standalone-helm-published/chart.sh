#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/helm-common.sh"

action="${1:-template}"
chart_ref="${CHART_REF:-pii-shield/pii-shield}"
release="${RELEASE:-pii-shield-demo}"
namespace="${NAMESPACE:-pii-shield-demo}"

helm_update_pii_shield_repo
prepare_pii_env_args

if [[ -z "${EXTRA_HELM_ARGS:-}" && -z "${VALUES_FILE:-}" ]]; then
  EXTRA_HELM_ARGS="--set demo.enabled=true"
fi

run_helm_chart_action "${action}" "${chart_ref}" "${release}" "${namespace}"
