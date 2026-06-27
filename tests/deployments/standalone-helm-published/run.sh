#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir standalone-helm-published)"

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chart.sh" upgrade

pod="$(kubectl get pod -n pii-shield-demo -l app.kubernetes.io/name=pii-shield -o jsonpath='{.items[0].metadata.name}')"
stream_fixture "${fixture}" | kubectl exec -i "${pod}" -n pii-shield-demo -c log-generator -- sh -c 'cat >> /var/log/app/output.log'
sleep "${DRAIN_SECONDS:-30}"
kubectl logs "${pod}" -n pii-shield-demo -c pii-shield > "${output_dir}/access.sanitized.log"
assert_sanitized_file "${output_dir}/access.sanitized.log"
