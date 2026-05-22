#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
chart_dir="${1:-${repo_root}/charts/pii-shield}"
watch_file="/var/log/app/output.log"

render_chart() {
  helm template pii-shield-runtime "$@"
}

container_block() {
  local rendered="$1"
  local container_name="$2"
  printf '%s\n' "$rendered" | awk -v container="$container_name" '
    $0 == "        - name: " container { in_block=1; print; next }
    in_block && /^        - name: / { exit }
    in_block { print }
  '
}

require_contains() {
  local text="$1"
  local pattern="$2"
  local message="$3"

  grep -q -- "$pattern" <<<"$text" || {
    echo "$message" >&2
    printf '%s\n' "$text" >&2
    exit 1
  }
}

require_not_contains() {
  local text="$1"
  local pattern="$2"
  local message="$3"

  if grep -q -- "$pattern" <<<"$text"; then
    echo "$message" >&2
    printf '%s\n' "$text" >&2
    exit 1
  fi
}

check_sidecar_runtime() {
  local rendered="$1"
  local sidecar
  sidecar="$(container_block "$rendered" "pii-shield")"
  if [[ -z "$sidecar" ]]; then
    echo "pii-shield container was not rendered" >&2
    exit 1
  fi

  require_not_contains "$sidecar" "/bin/sh" "pii-shield container must not require /bin/sh"
  require_contains "$sidecar" "command:" "pii-shield container must define command"
  require_contains "$sidecar" "- /pii-shield" "pii-shield container must run /pii-shield directly"
  require_contains "$sidecar" "args:" "pii-shield container must define args"
  require_contains "$sidecar" "- --watch-file" "pii-shield container must pass --watch-file"
  require_contains "$sidecar" "- \"${watch_file}\"" "pii-shield container must watch ${watch_file}"
}

default_render="$(render_chart "$chart_dir")"
if grep -q -- "name: log-generator" <<<"$default_render"; then
  echo "production render must not include the demo log generator" >&2
  exit 1
fi
require_not_contains "$default_render" "/bin/sh" "production render must not require /bin/sh"

check_sidecar_runtime "$default_render"
echo "OK: production render uses /pii-shield --watch-file without /bin/sh and does not include log-generator."

demo_render="$(render_chart "$chart_dir" --set demo.enabled=true)"
if ! grep -q -- "name: log-generator" <<<"$demo_render"; then
  echo "demo render must include the log generator when demo.enabled=true" >&2
  exit 1
fi

generator="$(container_block "$demo_render" "log-generator")"
if [[ -z "$generator" ]]; then
  echo "log-generator container block was not rendered" >&2
  exit 1
fi
require_contains "$generator" "/bin/sh" "demo log-generator should be the only shell-based container"

demo_without_generator="$(
  printf '%s\n' "$demo_render" | awk '
    /^        - name: log-generator$/ { in_generator=1; next }
    in_generator && /^        - name: / { in_generator=0 }
    !in_generator { print }
  '
)"
require_not_contains "$demo_without_generator" "/bin/sh" "only demo log-generator may require /bin/sh"

check_sidecar_runtime "$demo_render"
echo "OK: demo render includes log-generator while pii-shield sidecar remains scratch-compatible."
