# PII-Shield Configuration

PII-Shield is configured entirely via environment variables.

## Critical Security Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PII_SALT` | Random byte string used for HMAC hashing. **MUST be >16 chars in production.** | **No (Recommended)** | Randomly generated on startup (but ephemeral) |

> [!WARNING]
> If `PII_SALT` is not set, PII-Shield generates a random salt on startup. This means hashes will change every time the pod restarts, making it impossible to correlate logs across restarts. For production, **ALWAYS** set a persistent `PII_SALT`.

## Detection Tuning

| Variable | Description | Default |
|----------|-------------|---------|
| `PII_ENTROPY_THRESHOLD` | Shannon entropy threshold (3.0 - 8.0). Higher = fewer false positives, but might miss simple passwords. | `3.8` |
| `PII_MIN_SECRET_LENGTH` | Minimum length of a string to be considered a candidate token. | `6` |
| `PII_SENSITIVE_KEYS` | Comma-separated list of keys to *always* redact values for (case-insensitive). | `password,secret,token,key,api_key...` |
| `PII_SENSITIVE_KEY_PATTERNS` | Comma-separated list of regex patterns for key detection. | (empty) |

## Advanced Features

| Variable | Description | Default |
|----------|-------------|---------|
| `PII_ADAPTIVE_THRESHOLD` | Enable statistical learning. Scanner adjusts threshold based on traffic baseline. | `false` |
| `PII_ADAPTIVE_SAMPLES` | Number of samples to collect before activating adaptive mode. | `100` |
| `PII_DISABLE_BIGRAM_CHECK` | Disable English bigram validation. Set to `true` for non-English logs. | `false` |
| `PII_BIGRAM_DEFAULT_SCORE` | Log-probability score for unknown bigrams. | `-7.0` |

## Example (Kubernetes)

```yaml
env:
  - name: PII_SALT
    valueFrom:
      secretKeyRef:
        name: pii-shield-secrets
        key: salt
  - name: PII_ENTROPY_THRESHOLD
    value: "4.2"
  - name: PII_ADAPTIVE_THRESHOLD
    value: "true"
```
