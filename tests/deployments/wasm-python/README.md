# Python WASM SDK test

Installs `pii-shield-wasi` in `/tmp/pii-shield-python-check` and streams `notes/log_example/access.log` through the SDK.

```bash
tests/deployments/wasm-python/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/wasm-python`.
