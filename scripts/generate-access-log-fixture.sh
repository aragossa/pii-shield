#!/usr/bin/env bash
# Generate a synthetic access.log-style fixture with embedded fake PII for the
# deployment tests (tests/deployments/*). Real log fixtures must never leave
# the local machine or land in CI; this produces safe, representative data:
# plain traffic, emails, secrets/tokens/cards (must be redacted), and UUIDs
# (must NOT be redacted).
#
# Usage: scripts/generate-access-log-fixture.sh [output-file] [lines]
set -euo pipefail

out="${1:-${TMPDIR:-/tmp}/pii-shield-synthetic-access.log}"
lines="${2:-5000}"

python3 - "${out}" "${lines}" <<'PY'
import random
import string
import sys
import uuid

out, n = sys.argv[1], int(sys.argv[2])
random.seed(20260706)  # deterministic output for reproducible test runs

# TEST-NET address ranges (RFC 5737) - never real user IPs
ips = [f"192.0.2.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)]
paths = ["/", "/m/product/12345", "/filter/b874%2Cb32", "/api/v1/orders", "/login", "/healthz"]
uas = ["Mozilla/5.0 (X11; Linux x86_64)", "curl/8.4.0", "Go-http-client/2.0"]


def token(k=32):
    return "".join(random.choices(string.ascii_letters + string.digits, k=k))


def plain():
    return (f'{random.choice(ips)} - - [22/Jan/2026:03:56:19 +0330] '
            f'"GET {random.choice(paths)} HTTP/1.1" 200 {random.randint(100, 9000)} '
            f'"-" "{random.choice(uas)}"')


def email():
    return (f'{random.choice(ips)} - - [22/Jan/2026:03:56:20 +0330] '
            f'"POST /login HTTP/1.1" 200 512 "-" "user={token(8).lower()}@example.com"')


def secret():
    payload = random.choice([
        f"api_key={token(40)}",
        f"password=Sup3r{token(12)}!",
        f"authorization=Bearer {token(48)}",
        "aws_access_key_id=AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)),
        "card=4111111111111111",  # standard test PAN, passes Luhn
    ])
    return (f'{random.choice(ips)} - - [22/Jan/2026:03:56:21 +0330] '
            f'"POST /api/v1/orders HTTP/1.1" 201 64 "-" "{payload}"')


def safe():
    # UUIDs are on the scanner's safe list - they must survive redaction
    return (f'{random.choice(ips)} - - [22/Jan/2026:03:56:22 +0330] '
            f'"GET /api/v1/orders/{uuid.UUID(int=random.getrandbits(128))} HTTP/1.1" 200 128 "-" "-"')


with open(out, "w") as f:
    for _ in range(n):
        r = random.random()
        if r < 0.60:
            f.write(plain() + "\n")
        elif r < 0.75:
            f.write(email() + "\n")
        elif r < 0.90:
            f.write(secret() + "\n")
        else:
            f.write(safe() + "\n")

print(f"wrote {n} synthetic lines to {out}")
PY
