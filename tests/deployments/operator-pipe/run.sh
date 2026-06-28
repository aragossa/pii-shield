#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir operator-pipe)"
namespace="${NAMESPACE:-default}"
fail_policy="$(operator_fail_policy)"
warn_operator_unsupported_pii_env

# Make sure a local kind cluster exists (recreate it if it was deleted), then make sure
# the operator itself is installed in it — installing the operator if it is missing — so
# this test can run from scratch without any manual setup.
ensure_local_cluster
ensure_operator_installed
warn_pipe_agent_compat

kubectl label namespace "${namespace}" pii-shield.io/injection=enabled --overwrite
kubectl apply -n "${namespace}" -f - <<'YAML'
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: pipe-policy
spec:
  injectionMode: pipe
  failPolicy: ${fail_policy}
  originalCommand: sh -c 'while true; do sleep 3600; done'
YAML

# The pod has a fixed name and restartPolicy: Never. Re-applying it after a
# previous run re-runs the mutating webhook over the already-injected spec,
# which fails with "Duplicate value" / "pod updates may not add or remove
# containers". Delete any leftover first so each run starts from a fresh pod.
kubectl delete pod pii-pipe-test -n "${namespace}" --ignore-not-found --wait

kubectl apply -n "${namespace}" -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: pii-pipe-test
  labels:
    pii-shield.io/inject: "true"
  annotations:
    pii-shield.io/policy: pipe-policy
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: busybox:1.36
    command: ["/bin/sh", "-c"]
    args: ["while true; do sleep 3600; done"]
YAML

kubectl wait --for=condition=ready pod/pii-pipe-test -n "${namespace}" --timeout=120s
stream_fixture "${fixture}" | kubectl exec -i pii-pipe-test -n "${namespace}" -c app -- sh -c 'cat > /shared/log.pipe'
sleep "${DRAIN_SECONDS:-30}"
kubectl logs pii-pipe-test -n "${namespace}" -c pii-shield-sidecar > "${output_dir}/access.sanitized.log"
assert_sanitized_file "${output_dir}/access.sanitized.log"
