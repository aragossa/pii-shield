# PII-Shield Helm Chart

This Helm chart deploys **PII-Shield** as a scratch-compatible logging sidecar. The production path starts the container directly with `/pii-shield --watch-file ...`; it does not require `/bin/sh`, `tail`, or any other userspace tooling in the PII-Shield image.

PII-Shield leverages an advanced informational-entropy algorithm written in Go to catch new, unknown secrets and tokens that standard Regex engines miss, operating entirely without external network dependencies.

## Architecture

This chart provisions a **Sidecar Logging Pipeline**. The PII-Shield container watches a file on a shared `emptyDir` volume and writes sanitized output to `stdout`, ready for aggregation by standard Kubernetes log shippers.

By default, the chart renders the production-safe PII-Shield container only. Demo traffic generation is disabled so production installs do not start a synthetic log generator.

## Ultra-Lightweight Footprint

PII-Shield is built for extreme performance. This chart explicitly defines the following resource limits to showcase its minimal footprint, making it perfect for SRE teams:

*   **Memory Limit**: 30Mi
*   **CPU Limit**: 50m (0.05 Cores)

## Installation

Assuming you have added the repository:

```bash
helm repo add pii-shield https://pii-shield.github.io/pii-shield/
helm install pii-shield pii-shield/pii-shield
```

## Demo Mode

To run the built-in log generator for a live demo, enable `demo.enabled` explicitly:

```bash
helm install my-demo pii-shield/pii-shield --set demo.enabled=true
```

Once the demo pod is running, you can stream the sidecar's logs to see PII-Shield redacting data in real time:

```bash
kubectl logs -l app.kubernetes.io/name=pii-shield -c pii-shield -f
```

## Configuration

You can tune the redaction engine via `values.yaml` under `piiConfig`:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `salt` | string | `""` | Persistent HMAC salt. If empty, randomly generated on boot. |
| `requireStrongSalt` | string | `"false"` | Reject explicitly configured salts shorter than 16 bytes. |
| `entropyThreshold` | string | `"3.6"` | Shannon entropy cut-off determining what is considered a "secret". |
| `minSecretLength` | string | `"6"` | Minimum string length to apply entropy checks. |
| `sensitiveKeys` | string | `"password,secret,token,key,api_key"` | Key names mapped to `key=value` parsers to aggressively redact. |
| `adaptiveThreshold` | string | `"false"` | Auto-tuning baselines based on standard traffic. |

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `watchFile` | string | `"/var/log/app/output.log"` | File path watched by the PII-Shield sidecar. |
| `demo.enabled` | bool | `false` | Enables the demo-only Alpine log generator. |
| `metrics.serviceMonitor.enabled` | bool | `false` | Render a Prometheus Operator `ServiceMonitor`. |
| `metrics.prometheusRule.enabled` | bool | `false` | Render default Prometheus alert rules for PII-Shield availability, restarts, errors, latency, and missing throughput. |

## Operational Alerts

Prometheus Operator users can render the default alert rules:

```bash
helm install pii-shield pii-shield/pii-shield \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.prometheusRule.enabled=true
```

Tune alert labels and thresholds under `metrics.prometheusRule` before production rollout. Operational runbooks are documented in `docs/operational-runbooks.md`.
