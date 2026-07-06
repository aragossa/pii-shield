#!/usr/bin/env bash
set -euo pipefail

helm uninstall pii-shield-demo -n pii-shield-demo --ignore-not-found
kubectl delete namespace pii-shield-demo --ignore-not-found
