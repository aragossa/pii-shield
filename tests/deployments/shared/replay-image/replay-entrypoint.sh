#!/bin/sh
set -eu

input_file="${INPUT_FILE:-/fixtures/access.log}"
output_file="${OUTPUT_FILE:-/var/log/app/log.txt}"
replay_to_stdout="${REPLAY_TO_STDOUT:-false}"
sleep_seconds="${REPLAY_DONE_SLEEP_SECONDS:-3600}"

if [ ! -s "${input_file}" ]; then
  echo "input fixture is missing or empty: ${input_file}" >&2
  exit 1
fi

mkdir -p "$(dirname "${output_file}")"
: > "${output_file}"

echo "replaying ${input_file} into ${output_file}" >&2
if [ "${replay_to_stdout}" = "true" ]; then
  tee -a "${output_file}" < "${input_file}"
else
  cat "${input_file}" >> "${output_file}"
fi

echo "replay complete; keeping container alive for ${sleep_seconds}s" >&2
sleep "${sleep_seconds}"
