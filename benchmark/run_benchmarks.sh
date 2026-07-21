#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BASE_REF="${BASE_REF:-origin/main}"
RUNS="${RUNS:-7}"
LINES="${LINES:-500000}"
PAYLOAD_FILE="${PAYLOAD_FILE:-${SCRIPT_DIR}/payload.jsonl}"
RESULTS_DIR="${RESULTS_DIR:-${SCRIPT_DIR}/.benchmark-results}"
GO_BIN="${GO_BIN:-go}"

export GOCACHE="${GOCACHE:-${REPO_ROOT}/.gocache}"

old_bin="${RESULTS_DIR}/pii-shield-old"
new_bin="${RESULTS_DIR}/pii-shield-new"
timing_file="${RESULTS_DIR}/time.txt"
results_file="${RESULTS_DIR}/results.tsv"
summary_file="${RESULTS_DIR}/summary.txt"
tmp_baseline_dir=""

cleanup() {
  if [[ -n "${tmp_baseline_dir}" && -d "${tmp_baseline_dir}" ]]; then
    rm -rf "${tmp_baseline_dir}"
  fi
  rm -f "${old_bin}" "${new_bin}" "${timing_file}"
  rm -f "${PAYLOAD_FILE}"
}

usage() {
  cat <<EOF
Usage:
  BASE_REF=origin/main RUNS=7 LINES=500000 ./benchmark/run_benchmarks.sh

This is an end-to-end CLI throughput benchmark. It measures stdin scanning,
redaction, and stdout writes to /dev/null. For scanner-only microbenchmarks, run:
  go test -bench=. -benchmem ./pkg/scanner
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! [[ "${RUNS}" =~ ^[0-9]+$ ]] || [[ "${RUNS}" -lt 2 ]]; then
  echo "RUNS must be an integer >= 2" >&2
  exit 1
fi

if ! [[ "${LINES}" =~ ^[0-9]+$ ]] || [[ "${LINES}" -lt 1 ]]; then
  echo "LINES must be a positive integer" >&2
  exit 1
fi

trap cleanup EXIT

mkdir -p "${RESULTS_DIR}"

echo "=============================================="
echo " PII-Shield CLI Throughput Benchmark"
echo "=============================================="
echo "Baseline ref: ${BASE_REF}"
echo "Runs: ${RUNS}"
echo "Lines: ${LINES}"
echo

cd "${REPO_ROOT}"

if [[ "${SKIP_FETCH:-}" != "1" && "${BASE_REF}" == origin/* ]]; then
  echo "0. Fetching origin so ${BASE_REF} is current..."
  git fetch --quiet origin || {
    echo "Failed to fetch origin. Re-run with SKIP_FETCH=1 to use local refs." >&2
    exit 1
  }
fi

current_sha="$(git rev-parse --short HEAD)"
base_sha="$(git rev-parse --short "${BASE_REF}")"

echo "Current SHA: ${current_sha}"
echo "Baseline SHA: ${base_sha}"

if [[ "${current_sha}" == "${base_sha}" ]]; then
  echo "WARNING: current HEAD and ${BASE_REF} point to the same commit; this will only measure run-to-run noise." >&2
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "WARNING: current build includes uncommitted local changes." >&2
fi

echo
echo "1. Generating mixed test logs (${PAYLOAD_FILE})..."
awk -v n="${LINES}" '
  BEGIN {
    for (i = 1; i <= n; i++) {
      mod = i % 8
      if (mod == 0) {
        printf("{\"timestamp\":\"2026-05-22T08:%02d:%02dZ\",\"level\":\"INFO\",\"message\":\"User login attempt\",\"user_id\":\"user-%d\",\"token\":\"tok_live_%032x\",\"ip\":\"192.168.%d.%d\",\"credit_card\":\"4111111111111111\"}\n", i % 60, i % 60, i, i, i % 255, (i * 7) % 255)
      } else if (mod == 1) {
        printf("time=2026-05-22T08:%02d:%02dZ level=warn service=api request_id=req-%08x password=SecretPass%d status=401 latency_ms=%d\n", i % 60, i % 60, i, i, i % 300)
      } else if (mod == 2) {
        printf("{\"msg\":\"payment failed\",\"card\":\"5555555555554444\",\"email\":\"customer%d@example.com\",\"trace_id\":\"%040x\",\"commit_sha\":\"%040x\"}\n", i, i, i * 17)
      } else if (mod == 3) {
        printf("nginx access remote_addr=10.%d.%d.%d method=POST path=/v1/session authorization=Bearer eyJhbGciOiJIUzI1NiJ9.%032x response=200\n", i % 255, (i * 3) % 255, (i * 5) % 255, i)
      } else if (mod == 4) {
        printf("{\"nested\":\"{\\\"api_key\\\":\\\"sk_test_%032x\\\",\\\"safe_uuid\\\":\\\"550e8400-e29b-41d4-a716-446655440000\\\"}\",\"ok\":true}\n", i)
      } else if (mod == 5) {
        printf("INFO health_check ok instance=worker-%d memory_dump=[0a 1b 3c 4d 5e 6f] public_key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0gZ\n", i % 32)
      } else if (mod == 6) {
        printf("Error: database login failed for user admin secret=%032x endpoint=db.internal.local retry=%d\n", i * 97, i % 5)
      } else {
        printf("{\"event\":\"profile_update\",\"phone\":\"+1-202-555-%04d\",\"ssn\":\"123-45-6789\",\"note\":\"ordinary text with punctuation, quotes, and unicode-safe ascii\"}\n", i % 10000)
      }
    }
  }
' > "${PAYLOAD_FILE}"

payload_bytes="$(wc -c < "${PAYLOAD_FILE}" | tr -d ' ')"
payload_mb="$(awk -v bytes="${payload_bytes}" 'BEGIN { printf "%.6f", bytes / 1024 / 1024 }')"
payload_mb_display="$(awk -v mb="${payload_mb}" 'BEGIN { printf "%.2f", mb }')"
echo "   Payload size: ${payload_mb_display} MiB"

echo
echo "2. Building current branch..."
"${GO_BIN}" build -o "${new_bin}" ./cmd/cleaner

echo "3. Building baseline ${BASE_REF}..."
tmp_baseline_dir="$(mktemp -d)"
git archive "${base_sha}" | tar -x -C "${tmp_baseline_dir}"
(
  cd "${tmp_baseline_dir}"
  "${GO_BIN}" build -o "${old_bin}" ./cmd/cleaner
)
rm -rf "${tmp_baseline_dir}"
tmp_baseline_dir=""

printf "label\trun\tseconds\tmb_per_sec\n" > "${results_file}"

run_once() {
  local label="$1"
  local bin="$2"
  local run="$3"
  local seconds
  local mbps

  PII_METRICS_ENABLED=false /usr/bin/time -p "${bin}" < "${PAYLOAD_FILE}" > /dev/null 2> "${timing_file}"
  seconds="$(awk '/^real / { print $2 }' "${timing_file}")"
  mbps="$(awk -v mb="${payload_mb}" -v sec="${seconds}" 'BEGIN { if (sec <= 0) sec = 0.001; printf "%.2f", mb / sec }')"
  printf "%s\t%s\t%s\t%s\n" "${label}" "${run}" "${seconds}" "${mbps}" >> "${results_file}"
  printf "  %-8s run %d: %ss (%s MiB/s)\n" "${label}" "${run}" "${seconds}" "${mbps}"
}

echo
echo "----------------------------------------------"
echo " RUNNING END-TO-END CLI BENCHMARKS"
echo "----------------------------------------------"

for run in $(seq 1 "${RUNS}"); do
  if (( run % 2 == 1 )); then
    run_once "old" "${old_bin}" "${run}"
    run_once "new" "${new_bin}" "${run}"
  else
    run_once "new" "${new_bin}" "${run}"
    run_once "old" "${old_bin}" "${run}"
  fi
done

awk -F '\t' '
  NR == 1 { next }
  {
    label = $1
    seconds[label, ++count[label]] = $3
    mbps[label, count[label]] = $4
  }
  function sort_values(label, metric, arr, n, i, j, tmp) {
    n = count[label]
    for (i = 1; i <= n; i++) {
      arr[i] = metric == "seconds" ? seconds[label, i] + 0 : mbps[label, i] + 0
    }
    for (i = 1; i <= n; i++) {
      for (j = i + 1; j <= n; j++) {
        if (arr[j] < arr[i]) {
          tmp = arr[i]
          arr[i] = arr[j]
          arr[j] = tmp
        }
      }
    }
    return n
  }
  function median(arr, n) {
    if (n % 2 == 1) {
      return arr[(n + 1) / 2]
    }
    return (arr[n / 2] + arr[n / 2 + 1]) / 2
  }
  function percentile(arr, n, pct, idx) {
    idx = int(pct * n)
    if (idx < pct * n) {
      idx++
    }
    if (idx < 1) {
      idx = 1
    }
    if (idx > n) {
      idx = n
    }
    return arr[idx]
  }
  END {
    printf "\nSummary (median is the main number):\n"
    printf "%-8s %8s %8s %8s %8s %12s\n", "label", "median", "p95", "min", "max", "median MiB/s"
    for (label in count) {
      n = sort_values(label, "seconds", sorted_seconds)
      sort_values(label, "mbps", sorted_mbps)
      printf "%-8s %8.3f %8.3f %8.3f %8.3f %12.2f\n", label, median(sorted_seconds, n), percentile(sorted_seconds, n, 0.95), sorted_seconds[1], sorted_seconds[n], median(sorted_mbps, n)
    }
  }
' "${results_file}" | tee "${summary_file}"

echo
echo "Raw results: ${results_file}"
echo "Done."
