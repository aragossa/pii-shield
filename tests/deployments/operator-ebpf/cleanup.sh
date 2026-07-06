#!/usr/bin/env bash
set -euo pipefail

namespace="${NAMESPACE:-default}"
kubectl delete pod pii-ebpf-test -n "${namespace}" --ignore-not-found
kubectl delete piipolicy ebpf-policy -n "${namespace}" --ignore-not-found
