#!/usr/bin/env bash

helm_extra_args=()

prepare_helm_args() {
  set +u
  helm_extra_args=()
  if declare -p pii_helm_env_args >/dev/null 2>&1; then
    local copied_pii_helm_env_args=("${pii_helm_env_args[@]}")
    helm_extra_args+=("${copied_pii_helm_env_args[@]}")
  fi
  if [[ -n "${VALUES_FILE:-}" ]]; then
    helm_extra_args+=(--values "${VALUES_FILE}")
  fi
  if [[ -n "${EXTRA_HELM_ARGS:-}" ]]; then
    # Intentionally simple splitting for manual test use. Prefer VALUES_FILE for
    # complex values containing spaces.
    # shellcheck disable=SC2206
    local split_args=(${EXTRA_HELM_ARGS})
    helm_extra_args+=("${split_args[@]}")
  fi
  set -u
}

run_helm_chart_action() {
  local action="$1"
  local chart_ref="$2"
  local release="$3"
  local namespace="$4"
  local timeout="${HELM_TIMEOUT:-180s}"
  local revision="${REVISION:-}"

  prepare_helm_args

  case "${action}" in
    template)
      helm template "${release}" "${chart_ref}" \
        --namespace "${namespace}" \
        "${helm_extra_args[@]}"
      ;;
    lint)
      helm lint "${chart_ref}" "${helm_extra_args[@]}"
      ;;
    install)
      helm install "${release}" "${chart_ref}" \
        --namespace "${namespace}" \
        --create-namespace \
        --wait \
        --timeout "${timeout}" \
        "${helm_extra_args[@]}"
      ;;
    upgrade)
      helm upgrade --install "${release}" "${chart_ref}" \
        --namespace "${namespace}" \
        --create-namespace \
        --wait \
        --timeout "${timeout}" \
        "${helm_extra_args[@]}"
      ;;
    status)
      helm status "${release}" --namespace "${namespace}"
      ;;
    history)
      helm history "${release}" --namespace "${namespace}"
      ;;
    values)
      helm get values "${release}" --namespace "${namespace}" --all
      ;;
    manifest)
      helm get manifest "${release}" --namespace "${namespace}"
      ;;
    rollback)
      if [[ -n "${revision}" ]]; then
        helm rollback "${release}" "${revision}" \
          --namespace "${namespace}" \
          --wait \
          --timeout "${timeout}"
      else
        helm rollback "${release}" \
          --namespace "${namespace}" \
          --wait \
          --timeout "${timeout}"
      fi
      ;;
    uninstall)
      helm uninstall "${release}" --namespace "${namespace}" --ignore-not-found
      ;;
    *)
      cat >&2 <<EOF
unknown action: ${action}

Usage:
  $0 template|lint|install|upgrade|status|history|values|manifest|rollback|uninstall

Optional env:
  VALUES_FILE=/path/to/values.yaml
  EXTRA_HELM_ARGS='--set key=value --set other=value'
  HELM_TIMEOUT=180s
  REVISION=1
EOF
      exit 2
      ;;
  esac
}
