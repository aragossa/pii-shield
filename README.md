# PII-Shield 🛡️

**Zero-code log sanitization sidecar for Kubernetes.**
Prevents data leaks (GDPR/SOC2) by redacting PII from logs *before* they leave the pod.

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/thelisdeep/pii-shield)
![Go Report Card](https://goreportcard.com/badge/github.com/aragossa/pii-shield?v=1)
![Go Reference](https://pkg.go.dev/badge/github.com/aragossa/pii-shield.svg)
![Build Status](https://github.com/aragossa/pii-shield/actions/workflows/test.yml/badge.svg)
![Coverage Status](https://codecov.io/gh/aragossa/pii-shield/branch/main/graph/badge.svg)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/aragossa/pii-shield?sort=semver)

"Don't let PII poison your AI models." PII-Shield ensures that sensitive data never reaches your training dataset, saving you from GDPR-forced model retraining.

## Why PII-Shield?

Developers often forget to mask sensitive data. Traditional regex filters in Fluentd/Logstash are slow, hard to maintain, and consume expensive CPU on log aggregators.

**PII-Shield sits right next to your app container:**
- **Production Ready:** Optimized for Kubernetes sidecars with **ultra-low memory allocations** (zero-GC overhead on hot paths) and deterministic O(1) regex matching.
- **Context-Aware Entropy Analysis:** Detected high-entropy secrets even without keys (e.g. `Error: ... 44saCk9...`) by analyzing context keywords.
- **Custom Regex Rules:** Deterministic redaction for structured data (UUIDs, IDs) that overrides entropy checks, ensuring 100% compliance for known patterns.
- **100% Accuracy:** Verified against "Wild" stress tests including binary garbage, JSON nesting, and multilingual logs.
- **Deterministic Hashing:** Replaces secrets with unique hashes (e.g., `[HIDDEN:a1b2c]`), allowing QA to correlate errors without seeing the raw data.
- **Drop-in:** No code changes required. Works with any language (Node, Python, Java, Go).
- **Whitelist Support:** Explicitly allow safe patterns (e.g., git hashes, system IDs) using `PII_SAFE_REGEX_LIST` to prevent false positives.

## Performance Considerations

While PII-Shield is highly optimized, deep inspection of complex logs requires careful attention to configuration.
- **Text Logs:** Extremely fast (>100k lines/s).
- **JSON Logs:** Zero-allocation parsing (no `encoding/json` overhead). The scanner manually parses JSON structures to ensure high throughput (~7MB/s) without memory spikes.
- **Recommendation:** Usage is safe for high throughput. We use recursion safeguards to prevent stack overflows on deeply nested JSON.

## Installation

### Docker
Get the latest lightweight image from Docker Hub:
```bash
docker pull thelisdeep/pii-shield:latest
```

### Build from Source

You can build the binary directly from the source code:

```bash
go build -o pii-shield ./cmd/cleaner/main.go
```

## Configuration
See [CONFIGURATION.md](CONFIGURATION.md) for a full list of environment variables, including:
- `PII_SALT`: Custom HMAC salt (Required for production).
- `PII_ADAPTIVE_THRESHOLD`: Enable dynamic entropy baselines.
- `PII_DISABLE_BIGRAM_CHECK`: Optimize for non-English logs.
- `PII_CUSTOM_REGEX_LIST`: Custom regex rules for deterministic redaction.
- `PII_SAFE_REGEX_LIST`: Whitelist regex rules to ignore (matches are returned as-is).

### Entropy Sensitivity Table (Default Threshold: 3.6)

| Entropy | Data Type | Example |
|---------|-----------|---------|
| **0.0 - 3.0** | Common words, repeats | `password`, `admin`, `111111` |
| **3.0 - 3.6** | CamelCase, partial hashes | `ProgramCampaignInstanceJob`, `8f3a11b2c` |
| **3.6 - 4.5** | Paths, UUIDs, Weak Passwords | `/opt/application/runtime`, `P@ssw0rd2026!` |
| **4.5 - 5.0** | Medium Tokens | `E8s9d_2kL1` |
| **5.0+** | High Entropy Keys | (SHA-256, API Keys) |

## Quick Start
1. Test Locally (CLI)
You can pipe any log output through PII-Shield to see it in action immediately:

```bash
# Emulate a log with a sensitive password
echo "Error: User password=MySecretPass123! failed login" | docker run -i --rm thelisdeep/pii-shield:latest

# Output: Error: User password=[HIDDEN:8f3a11] failed login
```

2. Kubernetes (Sidecar Pattern)
To use PII-Shield as a pipe wrapper for your application, use an `initContainer` to copy the binary into a shared volume.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  volumes:
  - name: bin-dir
    emptyDir: {}
  
  # 1. Copy the PII-Shield binary to a shared volume
  initContainers:
  - name: install-shield
    image: thelisdeep/pii-shield:latest
    command: ["cp", "/bin/pii-shield", "/opt/bin/pii-shield"]
    volumeMounts:
    - name: bin-dir
      mountPath: /opt/bin

  # 2. Run your app and pipe logs through PII-Shield
  containers:
  - name: my-app
    image: my-app:1.0
    command: ["/bin/sh", "-c"]
    # Pipe stderr/stdout through the sanitizer
    args: ["./start-app.sh 2>&1 | /opt/bin/pii-shield"] 
    volumeMounts:
    - name: bin-dir
      mountPath: /opt/bin
```


## Verification
This project is verified with a comprehensive suite:
1. **Unit Tests**: Cover edge cases, multilingual support, and JSON integrity.
2. **Fuzzing**: Native Go fuzzing ensures crash safety against invalid inputs.
3. **Stress Testing**: `./full_stress_test.sh` validates 100% detection accuracy on mixed workloads.

## License
Distributed under the Apache 2.0 License. See `LICENSE` for more information.