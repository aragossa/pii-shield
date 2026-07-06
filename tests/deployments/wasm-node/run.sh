#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir wasm-node)"
workdir="${WORKDIR:-/tmp/pii-shield-node-check}"
prepare_pii_env_args

mkdir -p "${workdir}"
cd "${workdir}"
if [[ ! -f package.json ]]; then
  npm init -y >/dev/null
fi
npm install @aragossa/pii-shield-wasi

env "${pii_process_env_args[@]}" node - "${fixture}" "${output_dir}/access.sanitized.log" <<'JS'
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { PiiShield } = require('@aragossa/pii-shield-wasi');

(async () => {
  const input = process.argv[2];
  const output = process.argv[3];
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const config = {};
  if (process.env.PII_ENTROPY_THRESHOLD) config.entropyThreshold = Number(process.env.PII_ENTROPY_THRESHOLD);
  if (process.env.PII_CONFIDENCE_THRESHOLD) config.confidenceScore = Number(process.env.PII_CONFIDENCE_THRESHOLD);
  if (process.env.PII_SALT) config.salt = process.env.PII_SALT;
  if (process.env.PII_FAIL_POLICY) config.failPolicy = process.env.PII_FAIL_POLICY;
  const shield = await PiiShield.create(config);
  const rl = readline.createInterface({ input: fs.createReadStream(input) });
  const out = fs.createWriteStream(output);
  for await (const line of rl) {
    out.write(shield.redact(line) + '\n');
  }
  out.end();
})();
JS

assert_sanitized_file "${output_dir}/access.sanitized.log"
