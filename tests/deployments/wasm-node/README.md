# Node WASM SDK test

Installs `@aragossa/pii-shield-wasi` in `/tmp/pii-shield-node-check` and streams `notes/log_example/access.log` through the SDK.

```bash
tests/deployments/wasm-node/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/wasm-node`.
