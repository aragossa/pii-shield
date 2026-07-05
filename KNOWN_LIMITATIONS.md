# Known Limitations

PII-Shield is released and usable, but not yet fully production-hardened across all deployment modes. Production compliance deployments should account for the boundaries below.

## Kubernetes Logging

- The default file-based sidecar mode expects the application to write logs to the configured file path.
- Full transparent interception of standard Kubernetes `stdout`/`stderr` logs is not complete yet.
- Pipe mode is experimental and not recommended for production. It rewrites the target container command through `/bin/sh -c`, which can break distroless images (no shell), argument quoting, signal handling, and the app lifecycle. The webhook returns a warning when a pipe-mode policy is applied.

## Operator

- The Kubernetes operator is in stabilization. It supports policy objects and webhook injection, but advanced policy lifecycle management is still evolving.
- eBPF mode is experimental/R&D and should not be treated as production-ready interception.

## Scanner Configuration

- Set a persistent `PII_SALT` in production if deterministic hashes must remain stable across restarts.
- Adaptive entropy thresholding is experimental and should be validated against representative log traffic before enabling.
- Custom regex and safe regex rules should be tested with real log samples to avoid false positives or false negatives.

## Roadmap Boundaries

Proxy-Wasm gateway integration, a visual Control Plane, and production-grade eBPF interception are planned R&D areas rather than completed stable features.
