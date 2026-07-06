#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/helm-common.sh"

repo_root="$(deployment_repo_root)"
action="${1:-template}"
chart_ref="${CHART_REF:-${repo_root}/charts/pii-shield-operator}"
release="${RELEASE:-pii-shield-operator}"
namespace="${NAMESPACE:-operator-system}"
image_tag="${IMAGE_TAG:-manual}"
warn_operator_unsupported_pii_env

if [[ -z "${EXTRA_HELM_ARGS:-}" && -z "${VALUES_FILE:-}" ]]; then
  EXTRA_HELM_ARGS="--set image.repository=ghcr.io/pii-shield/pii-shield-operator --set image.tag=${image_tag} --set sidecar.image.repository=ghcr.io/pii-shield/pii-shield-agent --set sidecar.image.tag=${image_tag} --set webhook.useCertManager=false"
fi

# Reclaim fields that a manual `kubectl set` (field manager "kubectl-set") may
# own, e.g. env[AGENT_IMAGE].value; otherwise install/upgrade fails with a
# server-side apply ownership conflict. The flag is only valid for these actions.
if [[ "${action}" == "install" || "${action}" == "upgrade" ]]; then
  EXTRA_HELM_ARGS="${EXTRA_HELM_ARGS:-} --take-ownership"
fi

run_helm_chart_action "${action}" "${chart_ref}" "${release}" "${namespace}"
