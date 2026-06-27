#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir standalone-helm-local)"

# Build the standalone image from the current checkout and run the local chart
# against it. The chart's default image (thelisdeep/pii-shield) is an external
# published build that lags the local code, so a "-local" run must use the image
# it just built. A unique tag forces the Deployment to roll on each run.
image_tag="${IMAGE_TAG:-manual-$(date +%Y%m%d%H%M%S)}"
image="${IMAGE_REPO:-pii-shield}:${image_tag}"

ensure_local_cluster
docker build -t "${image}" "${repo_root}"
load_image_into_current_local_cluster "${image}"

EXTRA_HELM_ARGS="${EXTRA_HELM_ARGS:---set demo.enabled=true --set image.repository=${IMAGE_REPO:-pii-shield} --set image.tag=${image_tag} --set image.pullPolicy=IfNotPresent}" \
  "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chart.sh" upgrade

pod="$(kubectl get pod -n pii-shield-demo -l app.kubernetes.io/name=pii-shield -o jsonpath='{.items[0].metadata.name}')"
stream_fixture "${fixture}" | kubectl exec -i "${pod}" -n pii-shield-demo -c log-generator -- sh -c 'cat >> /var/log/app/output.log'
sleep "${DRAIN_SECONDS:-30}"
kubectl logs "${pod}" -n pii-shield-demo -c pii-shield > "${output_dir}/access.sanitized.log"
assert_sanitized_file "${output_dir}/access.sanitized.log"
