# PII-Shield Demonstrational Chart

This Helm chart deploys a live demonstration of **PII-Shield**: a zero-latency, AI-driven CLI tool designed to redact personally identifiable information (PII) from logs and standard streams.

PII-Shield leverages an advanced informational-entropy algorithm written in Go to catch new, unknown secrets and tokens that standard Regex engines miss, operating entirely without external network dependencies.

## Architecture

This chart provisions a **Sidecar Logging Pipeline**:
1. **App Container (`alpine`)**: Generates continuous mock application logs, including simulated Credit Cards, JWT tokens, and IP addresses.
2. **PII-Shield Sidecar**: Connects to the application's output file via a shared `emptyDir` memory volume (`tail -F`), pipelining the live data directly into the `/pii-shield` binary.

The sanitization results are outputted to the sidecar's `stdout`, ready for aggregation by standard Kubernetes log shippers.

## Ultra-Lightweight Footprint

PII-Shield is built for extreme performance. This chart explicitly defines the following resource limits to showcase its minimal footprint, making it perfect for SRE teams:

*   **Memory Limit**: 30Mi
*   **CPU Limit**: 50m (0.05 Cores)

## Installation

Assuming you have added the repository:

```bash
helm repo add pii-shield https://pii-shield.github.io/pii-shield/
helm install my-demo pii-shield/pii-shield
```

## Witness the Magic 🪄

Once the pods are running, you can stream the sidecar's logs to see PII-Shield redacting data in real-time:

```bash
kubectl logs -l app.kubernetes.io/name=pii-shield -c pii-shield -f
```

## Configuration

You can tune the redaction engine via `values.yaml` under `piiConfig`:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `salt` | string | `""` | Persistent HMAC salt. If empty, randomly generated on boot. |
| `entropyThreshold` | string | `"3.6"` | Shannon entropy cut-off determining what is considered a "secret". |
| `minSecretLength` | string | `"6"` | Minimum string length to apply entropy checks. |
| `sensitiveKeys` | string | `"password,secret,token,key,api_key"` | Key names mapped to `key=value` parsers to aggressively redact. |
| `adaptiveThreshold` | string | `"false"` | Auto-tuning baselines based on standard traffic. |
