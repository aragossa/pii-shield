# Configuration

PII-Shield is configured entirely via Environment Variables. No external config files are required.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PII_SALT` | Random | **Required for Prod.** A random string used to salt the HMAC hashes. **WARNING:** Ensure all replicas share the SAME salt, otherwise the same secret will have different hashes in different pods, breaking log aggregation. |
| `PII_ENTROPY_THRESHOLD` | `3.8` | The "randomness" score required to trigger redaction. Lower = more aggressive. Higher = less sensitive. |
| `PII_SENSITIVE_KEYS` | (Default list) | Comma-separated list of keys to always redact (e.g., `password,token,auth,secret`). |
| `PII_SENSITIVE_KEY_PATTERNS` | `(?i)(password|secret|key|token|auth|credential|pass|pwd)` | Regex pattern for matching sensitive keys. |
| `PII_MIN_SECRET_LENGTH` | `6` | Minimum length of a string to be considered a candidate for entropy scanning. |
| `PII_DISABLE_BIGRAM_CHECK` | `false` | Set to `true` if processing non-English logs to prevent false positives. |
| `PII_ADAPTIVE_THRESHOLD` | `false` | (Experimental) Enables dynamic threshold adjustment based on log traffic baselines. |
| `PII_BIGRAM_DEFAULT_SCORE` | `-7.0` | Sensitivity calibration for unknown bigrams. Lower values make the scanner more sensitive to random strings. |
| `PII_ADAPTIVE_SAMPLES` | `100` | Sample size for the adaptive entropy baseline (if `PII_ADAPTIVE_THRESHOLD` is enabled). |

### Default Sensitive Keys
If not overridden, PII-Shield looks for:
`password`, `passwd`, `pass`, `pwd`, `secret`, `key`, `api_key`, `access_token`, `auth_token`, `client_secret`, `cvv`, `card_number`, `stripe_token`.
