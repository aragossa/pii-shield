#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir wasm-python)"
venv="${VENV:-/tmp/pii-shield-python-check}"
prepare_pii_env_args

python3 -m venv "${venv}"
source "${venv}/bin/activate"
pip install pii-shield-wasi

env "${pii_process_env_args[@]}" python - "${fixture}" "${output_dir}/access.sanitized.log" <<'PY'
import os
import sys
from pathlib import Path
from pii_shield import PiiShield, PiiShieldConfig

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
dst.parent.mkdir(parents=True, exist_ok=True)

config = PiiShieldConfig(
    entropy_threshold=float(os.environ["PII_ENTROPY_THRESHOLD"]) if os.environ.get("PII_ENTROPY_THRESHOLD") else None,
    confidence_score=float(os.environ["PII_CONFIDENCE_THRESHOLD"]) if os.environ.get("PII_CONFIDENCE_THRESHOLD") else None,
    salt=os.environ.get("PII_SALT"),
    fail_policy=os.environ.get("PII_FAIL_POLICY", "open"),
)
shield = PiiShield(config)
with src.open("r", errors="replace") as inp, dst.open("w") as out:
    for line in inp:
        out.write(shield.redact(line.rstrip("\n")) + "\n")
PY

assert_sanitized_file "${output_dir}/access.sanitized.log"
