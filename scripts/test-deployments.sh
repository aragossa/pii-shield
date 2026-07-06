#!/usr/bin/env bash
# Run the deployment test matrix (tests/deployments/*) by group.
#
# Usage: scripts/test-deployments.sh [group|path ...]
#
# Groups:
#   local              no cluster, locally built artifacts: local-binary docker-local
#   published          no cluster, published artifacts:     docker-ghcr wasm-node wasm-python
#   cluster            kind, local charts/images:           standalone-helm-local operator-helm-local
#                                                           operator-local-images operator-kustomize
#                                                           operator-pipe operator-ebpf
#   cluster-published  kind, published charts:              standalone-helm-published operator-helm-published
#   all                every path (default)
#
# Individual path names (folder names under tests/deployments/) may be passed
# instead of a group.
#
# Fixture resolution: PII_SHIELD_ACCESS_LOG if set, else notes/log_example/access.log
# if present, else a synthetic fixture is generated (safe for CI - contains no
# real data; see scripts/generate-access-log-fixture.sh).
#
# Each path runs its run.sh and then its cleanup.sh (if present) regardless of
# the outcome. All requested paths run even if earlier ones fail; a summary is
# printed and the exit code is non-zero if anything failed.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOYMENTS_DIR="${ROOT_DIR}/tests/deployments"

LOCAL_PATHS=(local-binary docker-local)
PUBLISHED_PATHS=(docker-ghcr wasm-node wasm-python)
CLUSTER_PATHS=(standalone-helm-local operator-helm-local operator-local-images operator-kustomize operator-pipe operator-ebpf)
CLUSTER_PUBLISHED_PATHS=(standalone-helm-published operator-helm-published)

resolve_paths() {
  case "$1" in
    local) printf '%s\n' "${LOCAL_PATHS[@]}" ;;
    published) printf '%s\n' "${PUBLISHED_PATHS[@]}" ;;
    cluster) printf '%s\n' "${CLUSTER_PATHS[@]}" ;;
    cluster-published) printf '%s\n' "${CLUSTER_PUBLISHED_PATHS[@]}" ;;
    all) printf '%s\n' "${LOCAL_PATHS[@]}" "${PUBLISHED_PATHS[@]}" "${CLUSTER_PATHS[@]}" "${CLUSTER_PUBLISHED_PATHS[@]}" ;;
    *)
      if [[ -x "${DEPLOYMENTS_DIR}/$1/run.sh" ]]; then
        printf '%s\n' "$1"
      else
        echo "unknown group or path: $1" >&2
        return 1
      fi
      ;;
  esac
}

paths=()
for arg in "${@:-all}"; do
  while IFS= read -r p; do paths+=("${p}"); done < <(resolve_paths "${arg}") || exit 2
done

# Resolve the fixture once so every path uses the same input.
if [[ -z "${PII_SHIELD_ACCESS_LOG:-}" ]]; then
  if [[ -s "${ROOT_DIR}/notes/log_example/access.log" ]]; then
    export PII_SHIELD_ACCESS_LOG="${ROOT_DIR}/notes/log_example/access.log"
  else
    synthetic="${TMPDIR:-/tmp}/pii-shield-synthetic-access.log"
    "${ROOT_DIR}/scripts/generate-access-log-fixture.sh" "${synthetic}"
    export PII_SHIELD_ACCESS_LOG="${synthetic}"
  fi
fi
echo "fixture: ${PII_SHIELD_ACCESS_LOG}"

declare -a results
failed=0
for path in "${paths[@]}"; do
  echo ""
  echo "=========================================================="
  echo "=== ${path}"
  echo "=========================================================="
  if "${DEPLOYMENTS_DIR}/${path}/run.sh"; then
    results+=("PASS  ${path}")
  else
    results+=("FAIL  ${path}")
    failed=1
  fi
  if [[ -x "${DEPLOYMENTS_DIR}/${path}/cleanup.sh" ]]; then
    "${DEPLOYMENTS_DIR}/${path}/cleanup.sh" || echo "warning: cleanup failed for ${path}" >&2
  fi
done

echo ""
echo "=== deployment matrix summary ==="
printf '%s\n' "${results[@]}"
exit "${failed}"
