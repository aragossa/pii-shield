#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
cleanup_operator_replay
helm uninstall pii-shield-operator -n operator-system --ignore-not-found
