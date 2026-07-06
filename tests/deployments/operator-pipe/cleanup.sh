#!/usr/bin/env bash
set -euo pipefail

namespace="${NAMESPACE:-default}"
kubectl delete pod pii-pipe-test -n "${namespace}" --ignore-not-found
kubectl delete piipolicy pipe-policy -n "${namespace}" --ignore-not-found
