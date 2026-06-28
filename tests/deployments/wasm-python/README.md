# Python WASM SDK test

Installs `pii-shield-wasi` and streams `notes/log_example/access.log` through the SDK,
**inside a Linux container** (see "Why Docker" below). Requires Docker.

```bash
tests/deployments/wasm-python/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/wasm-python`.

The redaction program is [`redact.py`](redact.py); it runs in `python:3.11-slim` (override
with `PII_PY_IMAGE`). The fixture is mounted read-only at `/fixture` and the output dir at
`/out`.

## Why Docker: the SDK is killed on macOS (`Killed: 9`)

Run natively on macOS, the Python SDK is killed with `Killed: 9` (SIGKILL) ~2s after the
WASM module loads and never finishes. It is **not** a bug in pii-shield, the WASM module,
the fixture, or this script — it is a `wasmtime` (the SDK's runtime) problem specific to
macOS, so the test runs in a Linux container instead.

Evidence:

- The process is SIGKILLed ~2s after the WASM module is loaded, regardless of input,
  number of `redact` calls, or workload — it dies even when idle after loading, with
  zero `redact` calls.
- Not memory pressure (RSS ~185MB at death, ~49% RAM free, no jetsam/memorystatus
  kernel events) and not input-dependent (a constant string crashes too).
- The exact same `pii-shield-wasi.wasm` (byte-identical, same sha256) runs the full
  3.3GB fixture fine under Node (`wasm-node`) on the same Mac, and a trivial wasm module
  survives under `wasmtime` — so neither the module nor wasmtime-in-general is at fault.
- On Linux (same arm64 CPU, in Docker) the identical SDK processes 3,000,000 lines and
  survives the idle test cleanly — only the OS differs.
