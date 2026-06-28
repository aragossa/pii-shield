#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"

namespace="${NAMESPACE:-default}"

# Make sure a local kind cluster exists (recreate it if it was deleted), then make sure
# the operator itself is installed in it — installing the operator if it is missing — so
# this test can run from scratch without any manual setup.
ensure_local_cluster
ensure_operator_installed

kubectl label namespace "${namespace}" pii-shield.io/injection=enabled --overwrite
kubectl apply -n "${namespace}" -f - <<'YAML'
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: ebpf-policy
spec:
  injectionMode: ebpf
YAML

# Fixed-name pod: delete any leftover from a previous run so re-applying does not
# re-trigger webhook injection over an already-mutated spec (Duplicate value /
# pod updates may not add or remove containers).
kubectl delete pod pii-ebpf-test -n "${namespace}" --ignore-not-found --wait

kubectl apply -n "${namespace}" -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: pii-ebpf-test
  labels:
    pii-shield.io/inject: "true"
  annotations:
    pii-shield.io/policy: ebpf-policy
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "60"]
YAML

kubectl get pod pii-ebpf-test -n "${namespace}" -o yaml | grep -A20 pii-shield-sidecar
kubectl describe pod pii-ebpf-test -n "${namespace}"
echo "eBPF mode is experimental; this script checks mutation/rendering only."
