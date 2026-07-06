#!/usr/bin/env bash

pii_env_names=(
  PII_SALT
  PII_REQUIRE_STRONG_SALT
  PII_ENTROPY_THRESHOLD
  PII_CONFIDENCE_THRESHOLD
  PII_MIN_SECRET_LENGTH
  PII_SENSITIVE_KEYS
  PII_SENSITIVE_KEY_PATTERNS
  PII_ADAPTIVE_THRESHOLD
  PII_ADAPTIVE_SAMPLES
  PII_DISABLE_BIGRAM_CHECK
  PII_BIGRAM_DEFAULT_SCORE
  PII_FAIL_POLICY
  PII_CUSTOM_REGEX_LIST
  PII_SAFE_REGEX_LIST
  PII_METRICS_ENABLED
  PII_METRICS_PORT
)

pii_docker_env_args=()
pii_process_env_args=()
pii_helm_env_args=()
pii_docker_port_args=()

helm_escape_set_value() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//,/\\,}"
  printf '%s\n' "${value}"
}

load_pii_env_file() {
  if [[ -n "${PII_ENV_FILE:-}" ]]; then
    if [[ ! -f "${PII_ENV_FILE}" ]]; then
      echo "PII_ENV_FILE does not exist: ${PII_ENV_FILE}" >&2
      exit 1
    fi
    set -a
    # shellcheck disable=SC1090
    source "${PII_ENV_FILE}"
    set +a
  fi
}

set_default_pii_env() {
  : "${PII_SALT:=manual-test-salt-12345}"
  : "${PII_REQUIRE_STRONG_SALT:=true}"
  : "${PII_FAIL_POLICY:=open}"
}

prepare_pii_env_args() {
  load_pii_env_file
  set_default_pii_env

  pii_docker_env_args=()
  pii_process_env_args=()
  pii_helm_env_args=()
  pii_docker_port_args=()

  local name value
  for name in "${pii_env_names[@]}"; do
    if [[ -n "${!name+x}" ]]; then
      value="${!name}"
      pii_docker_env_args+=(-e "${name}=${value}")
      pii_process_env_args+=("${name}=${value}")

      case "${name}" in
        PII_SALT)
          pii_helm_env_args+=(--set-string "piiConfig.salt=$(helm_escape_set_value "${value}")")
          ;;
        PII_REQUIRE_STRONG_SALT)
          pii_helm_env_args+=(--set-string "piiConfig.requireStrongSalt=$(helm_escape_set_value "${value}")")
          ;;
        PII_ENTROPY_THRESHOLD)
          pii_helm_env_args+=(--set-string "piiConfig.entropyThreshold=$(helm_escape_set_value "${value}")")
          ;;
        PII_MIN_SECRET_LENGTH)
          pii_helm_env_args+=(--set-string "piiConfig.minSecretLength=$(helm_escape_set_value "${value}")")
          ;;
        PII_SENSITIVE_KEYS)
          pii_helm_env_args+=(--set-string "piiConfig.sensitiveKeys=$(helm_escape_set_value "${value}")")
          ;;
        PII_ADAPTIVE_THRESHOLD)
          pii_helm_env_args+=(--set-string "piiConfig.adaptiveThreshold=$(helm_escape_set_value "${value}")")
          ;;
        PII_FAIL_POLICY)
          pii_helm_env_args+=(--set-string "piiConfig.failPolicy=$(helm_escape_set_value "${value}")")
          ;;
        PII_CUSTOM_REGEX_LIST)
          pii_helm_env_args+=(--set-string "piiConfig.customRegexList=$(helm_escape_set_value "${value}")")
          ;;
        PII_SAFE_REGEX_LIST)
          pii_helm_env_args+=(--set-string "piiConfig.safeRegexList=$(helm_escape_set_value "${value}")")
          ;;
        PII_METRICS_ENABLED)
          if [[ "${value}" == "true" || "${value}" == "1" ]]; then
            pii_helm_env_args+=(--set "metrics.enabled=true")
          else
            pii_helm_env_args+=(--set "metrics.enabled=false")
          fi
          ;;
        PII_METRICS_PORT)
          pii_helm_env_args+=(--set "metrics.port=${value}")
          ;;
      esac
    fi
  done

  if [[ "${PII_METRICS_ENABLED:-}" == "true" || "${PII_METRICS_ENABLED:-}" == "1" ]]; then
    local metrics_port="${PII_METRICS_PORT:-9090}"
    local metrics_host_port="${PII_METRICS_HOST_PORT:-${metrics_port}}"
    pii_docker_port_args+=(-p "${metrics_host_port}:${metrics_port}")
  fi
}

enable_runtime_metrics_by_default() {
  : "${PII_METRICS_ENABLED:=true}"
  : "${PII_METRICS_PORT:=9090}"
}

print_runtime_metrics_hint() {
  if [[ "${PII_METRICS_ENABLED:-}" == "true" || "${PII_METRICS_ENABLED:-}" == "1" ]]; then
    local metrics_port="${PII_METRICS_PORT:-9090}"
    local metrics_host_port="${PII_METRICS_HOST_PORT:-${metrics_port}}"
    cat <<EOF
Prometheus metrics enabled while access.log is being processed.
Open another terminal and run:

  watch -n 2 "curl -s http://127.0.0.1:${metrics_host_port}/metrics | grep -E 'piishield_processed_bytes_total|piishield_redaction_events_total|piishield_errors_total'"

EOF
  fi
}

operator_fail_policy() {
  load_pii_env_file
  printf '%s\n' "${PII_FAIL_POLICY:-open}"
}

warn_operator_unsupported_pii_env() {
  load_pii_env_file
  local unsupported=()
  local name
  for name in "${pii_env_names[@]}"; do
    case "${name}" in
      PII_FAIL_POLICY) ;;
      *)
        if [[ -n "${!name+x}" ]]; then
          unsupported+=("${name}")
        fi
        ;;
    esac
  done

  if [[ "${#unsupported[@]}" -gt 0 ]]; then
    echo "WARNING: operator-injected sidecars currently do not receive scanner env vars from PiiPolicy." >&2
    echo "WARNING: ignored for operator replay: ${unsupported[*]}" >&2
    echo "WARNING: only PII_FAIL_POLICY is mapped to PiiPolicy.spec.failPolicy." >&2
  fi
}

print_pii_env_help() {
  cat <<'EOF'
PII variable controls:
  PII_ENV_FILE=/path/to/env-file
  PII_SALT=manual-test-salt-12345
  PII_REQUIRE_STRONG_SALT=true
  PII_ENTROPY_THRESHOLD=3.6
  PII_CONFIDENCE_THRESHOLD=1.0
  PII_MIN_SECRET_LENGTH=6
  PII_SENSITIVE_KEYS=password,secret,token,key,api_key
  PII_SENSITIVE_KEY_PATTERNS='token|secret'
  PII_ADAPTIVE_THRESHOLD=false
  PII_ADAPTIVE_SAMPLES=100
  PII_DISABLE_BIGRAM_CHECK=false
  PII_BIGRAM_DEFAULT_SCORE=-7.0
  PII_FAIL_POLICY=open
  PII_CUSTOM_REGEX_LIST='[{"pattern":"^TX-\\d{5}$","name":"TX"}]'
  PII_SAFE_REGEX_LIST='[{"pattern":"^[a-f0-9]{7}$","name":"GitShortSHA"}]'
  PII_METRICS_ENABLED=false
  PII_METRICS_PORT=9090

Notes:
  Docker and local-binary paths receive all listed variables.
  Standalone Helm paths map supported variables to charts/pii-shield values.
  Operator paths currently map only PII_FAIL_POLICY to PiiPolicy.spec.failPolicy.
EOF
}
