# PII-Shield 🛡️

**Zero-code log sanitization sidecar for Kubernetes.**
Prevents data leaks (GDPR/SOC2) by redacting PII from logs *before* they leave the pod.

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/thelisdeep/pii-shield)
![Go Report Card](https://goreportcard.com/badge/github.com/thelisdeep/pii-shield)

## Why PII-Shield?

Developers often forget to mask sensitive data. Traditional regex filters in Fluentd/Logstash are slow, hard to maintain, and consume expensive CPU on log aggregators.

**PII-Shield sits right next to your app container:**
- 🚀 **High Performance:** Written in Go, <30µs latency per line.
- 🧠 **Entropy Analysis:** Detects high-entropy secrets (API keys, passwords) without knowing their format.
- 🔍 **Deterministic Hashing:** Replaces secrets with unique hashes (e.g., `[HIDDEN:a1b2c]`), allowing QA to correlate errors without seeing the raw data.
- 📦 **Drop-in:** No code changes required. Works with any language (Node, Python, Java, Go).

## 📥 Installation

### Docker
Get the latest lightweight image from Docker Hub:
```bash
docker pull thelisdeep/pii-shield:latest
```

## ⚡ Quick Start
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


## 📜 License
Distributed under the Apache 2.0 License. See `LICENSE` for more information.