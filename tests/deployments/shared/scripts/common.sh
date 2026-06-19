#!/usr/bin/env bash

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pii-env.sh"

deployment_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd
}

require_access_log_fixture() {
  local repo_root="$1"
  local fixture="${PII_SHIELD_ACCESS_LOG:-${repo_root}/notes/log_example/access.log}"
  if [[ ! -s "${fixture}" ]]; then
    echo "missing fixture: ${fixture}" >&2
    exit 1
  fi
  printf '%s\n' "${fixture}"
}

ensure_output_dir() {
  local name="$1"
  local output_dir="${OUTPUT_DIR:-/tmp/pii-shield-sanitized/${name}}"
  mkdir -p "${output_dir}"
  printf '%s\n' "${output_dir}"
}

count_hidden() {
  local file="$1"
  grep -c '\[HIDDEN:' "${file}" || true
}

assert_sanitized_file() {
  local file="$1"
  local min_hidden_count="${MIN_HIDDEN_COUNT:-1}"
  local lines hidden
  lines="$(wc -l < "${file}" | tr -d ' ')"
  hidden="$(count_hidden "${file}")"
  echo "${file}: lines=${lines} hidden=${hidden}"
  if [[ "${lines}" -eq 0 ]]; then
    echo "FAIL: ${file} is empty" >&2
    exit 1
  fi
  if [[ "${hidden}" -lt "${min_hidden_count}" ]]; then
    echo "FAIL: hidden count ${hidden} is below ${min_hidden_count}" >&2
    exit 1
  fi
}

helm_update_pii_shield_repo() {
  helm repo add pii-shield https://pii-shield.github.io/pii-shield/ >/dev/null
  helm repo update pii-shield
}

install_cert_manager() {
  echo "cert-manager CRDs missing; installing cert-manager..." >&2
  helm repo add jetstack https://charts.jetstack.io >/dev/null
  helm repo update jetstack
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --create-namespace \
    --set crds.enabled=true
  kubectl wait --for=condition=Available deployment/cert-manager-webhook \
    -n cert-manager --timeout="${CERT_MANAGER_WAIT_TIMEOUT:-180s}"
}

require_cert_manager_crds() {
  if kubectl get crd certificates.cert-manager.io issuers.cert-manager.io >/dev/null 2>&1; then
    return
  fi

  if [[ "${CERT_MANAGER_AUTO_INSTALL:-true}" == "true" ]]; then
    install_cert_manager
    if kubectl get crd certificates.cert-manager.io issuers.cert-manager.io >/dev/null 2>&1; then
      return
    fi
    echo "cert-manager install completed but CRDs are still missing" >&2
  fi

  cat >&2 <<'EOF'
cert-manager CRDs are required for this deployment path.

Install cert-manager in the current cluster first:

  helm repo add jetstack https://charts.jetstack.io
  helm repo update jetstack
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --create-namespace \
    --set crds.enabled=true
  kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=180s
  kubectl get crd certificates.cert-manager.io issuers.cert-manager.io

Then re-run the deployment script.
EOF
  exit 1
}

# Guard for deployment paths that do not install the operator themselves and
# assume it is already running (operator-pipe, operator-ebpf). Without it, the
# first `kubectl apply` of a PiiPolicy fails with a cryptic API error:
#   the server could not find the requested resource (post piipolicies...)
require_operator_installed() {
  if kubectl get crd piipolicies.core.pii-shield.io >/dev/null 2>&1; then
    return
  fi

  cat >&2 <<'EOF'
The PII-Shield operator is not installed in this cluster
(CRD piipolicies.core.pii-shield.io not found).

This deployment path assumes the operator is already running. Install it first
with one of the operator deployment paths, e.g.:

  tests/deployments/operator-kustomize/run.sh
  # or
  tests/deployments/operator-helm-local/chart.sh upgrade

Then re-run this script.
EOF
  exit 1
}

# Print the agent image the operator will inject, if discoverable. The operator
# deployment name differs by install path (operator-controller-manager for
# kustomize, pii-shield-operator for helm), so scan all deployments in the
# operator namespace for the AGENT_IMAGE env var.
operator_agent_image() {
  kubectl get deploy -n "${OPERATOR_NAMESPACE:-operator-system}" \
    -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*].env[?(@.name=="AGENT_IMAGE")]}{.value}{"\n"}{end}{end}' \
    2>/dev/null | head -1
}

# Pipe mode needs an agent that *follows* the injected FIFO (blocks waiting for a
# writer) instead of exiting on the empty pipe. Released agents through 2.1.0
# exit and crash-loop, so the native-sidecar never stays running and the pod
# never becomes Ready — the readiness wait then times out with no explanation.
# Warn up front (non-blocking) so that timeout is understood when it happens.
warn_pipe_agent_compat() {
  [[ "${PIPE_AGENT_COMPAT_SKIP:-false}" == "true" ]] && return 0
  local img
  img="$(operator_agent_image)"
  [[ -z "${img}" ]] && return 0

  echo "operator injects agent image: ${img}" >&2
  case "${img}" in
    ghcr.io/pii-shield/pii-shield-agent:*)
      cat >&2 <<EOF
WARNING: '${img}' is a published agent image. Released agents through 2.1.0 exit
on the empty pipe FIFO and crash-loop, so pii-pipe-test will not become Ready and
the readiness wait below will time out.

Pipe mode is a dev path: point the operator at a locally built agent first.

  docker build -t pii-shield-agent:manual -f Dockerfile.agent .
  kind load docker-image pii-shield-agent:manual --name "\${KIND_CLUSTER:-pii-shield-manual}"
  kubectl set env deployment -n "${OPERATOR_NAMESPACE:-operator-system}" --all AGENT_IMAGE=pii-shield-agent:manual
  kubectl rollout status deployment -n "${OPERATOR_NAMESPACE:-operator-system}" --timeout=120s

Set PIPE_AGENT_COMPAT_SKIP=true to silence this warning.
EOF
      ;;
  esac
}

load_image_into_current_local_cluster() {
  local image="$1"
  local context
  context="$(kubectl config current-context)"

  if [[ "${context}" == kind-* ]]; then
    local cluster="${KIND_CLUSTER:-${context#kind-}}"
    kind load docker-image "${image}" --name "${cluster}"
  elif [[ "${context}" == minikube ]]; then
    minikube image load "${image}"
  else
    echo "current context is ${context}; cannot infer local image load target" >&2
    echo "push ${image} to a registry or switch to kind/minikube" >&2
    exit 1
  fi
}

build_replay_image() {
  local repo_root="$1"
  local image="${REPLAY_IMAGE:-pii-shield-access-log-replay:manual}"
  require_access_log_fixture "${repo_root}" >/dev/null
  docker build -f "${repo_root}/tests/deployments/shared/replay-image/Dockerfile" -t "${image}" "${repo_root}"
  echo "built ${image}"
}

load_replay_image() {
  local image="${REPLAY_IMAGE:-pii-shield-access-log-replay:manual}"
  load_image_into_current_local_cluster "${image}"
}

deploy_operator_replay_pods() {
  local namespace="${NAMESPACE:-default}"
  local replicas="${REPLICAS:-4}"
  local image="${REPLAY_IMAGE:-pii-shield-access-log-replay:manual}"
  local policy_name="${POLICY_NAME:-access-log-replay-policy}"
  local app_label="${APP_LABEL:-pii-access-log-replay}"
  local fail_policy
  fail_policy="$(operator_fail_policy)"
  warn_operator_unsupported_pii_env

  kubectl label namespace "${namespace}" pii-shield.io/injection=enabled --overwrite

  # Replay pods use restartPolicy: Never, so a previous run leaves them Completed.
  # kubectl apply treats the identical manifest as unchanged and never recreates
  # them, which makes the readiness wait below time out forever. Delete any
  # leftovers first so each run starts from fresh pods.
  kubectl delete pod -n "${namespace}" -l "app=${app_label}" --ignore-not-found --wait

  kubectl apply -n "${namespace}" -f - <<YAML
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: ${policy_name}
spec:
  injectionMode: file
  logPath: /var/log/app/log.txt
  failPolicy: ${fail_policy}
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 500m
      memory: 256Mi
YAML

  for i in $(seq 1 "${replicas}"); do
    kubectl apply -n "${namespace}" -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${app_label}-${i}
  labels:
    app: ${app_label}
    pii-shield.io/inject: "true"
  annotations:
    pii-shield.io/policy: ${policy_name}
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: ${image}
    imagePullPolicy: IfNotPresent
    env:
    - name: OUTPUT_FILE
      value: /var/log/app/log.txt
    - name: REPLAY_TO_STDOUT
      value: "false"
    - name: REPLAY_DONE_SLEEP_SECONDS
      value: "3600"
YAML
  done

  kubectl wait --for=condition=ready pod -n "${namespace}" -l "app=${app_label}" --timeout=180s

  for i in $(seq 1 "${replicas}"); do
    local pod="${app_label}-${i}"
    echo "=== ${pod} containers ==="
    kubectl get pod "${pod}" -n "${namespace}" -o jsonpath='{.spec.initContainers[*].name}{"\n"}{.spec.containers[*].name}{"\n"}'
  done
}

collect_operator_replay_logs() {
  local output_name="$1"
  local namespace="${NAMESPACE:-default}"
  local replicas="${REPLICAS:-4}"
  local app_label="${APP_LABEL:-pii-access-log-replay}"
  local output_dir
  output_dir="$(ensure_output_dir "${output_name}")"
  local drain_seconds="${DRAIN_SECONDS:-30}"
  local wait_timeout_seconds="${WAIT_TIMEOUT_SECONDS:-1800}"

  local deadline=$((SECONDS + wait_timeout_seconds))
  for i in $(seq 1 "${replicas}"); do
    local pod="${app_label}-${i}"
    while ! kubectl logs "${pod}" -n "${namespace}" -c app 2>/dev/null | grep -q "replay complete"; do
      if [[ "${SECONDS}" -ge "${deadline}" ]]; then
        echo "FAIL: timed out waiting for ${pod} replay completion" >&2
        kubectl logs "${pod}" -n "${namespace}" -c app --tail=50 || true
        exit 1
      fi
      sleep 5
    done
    echo "${pod}: replay complete"
  done

  sleep "${drain_seconds}"

  for i in $(seq 1 "${replicas}"); do
    local pod="${app_label}-${i}"
    local out="${output_dir}/${pod}.sanitized.log"
    kubectl logs "${pod}" -n "${namespace}" -c pii-shield-sidecar > "${out}"
    assert_sanitized_file "${out}"
  done

  ls -lh "${output_dir}"
}

cleanup_operator_replay() {
  local namespace="${NAMESPACE:-default}"
  local app_label="${APP_LABEL:-pii-access-log-replay}"
  local policy_name="${POLICY_NAME:-access-log-replay-policy}"
  kubectl delete pod -n "${namespace}" -l "app=${app_label}" --ignore-not-found
  kubectl delete piipolicy -n "${namespace}" "${policy_name}" --ignore-not-found
}
