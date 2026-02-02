# Kubernetes Integration

Since PII-Shield is a standalone binary, the most reliable way to use it in Kubernetes (MVP) is as a **Pipe Wrapper** using an `initContainer`.

## Implementation Guide

This pattern copies the PII-Shield binary into your Pod and pipes your application's output through it.

### 1. Update your Pod Spec (Deployment.yaml)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  # Create a shared volume for the binary
  volumes:
  - name: bin-dir
    emptyDir: {}

  # InitContainer: Copies the PII-Shield binary to the shared volume
  initContainers:
  - name: install-shield
    image: thelisdeep/pii-shield:latest
    # Binary is located at root /pii-shield
    command: ["cp", "/pii-shield", "/opt/bin/pii-shield"]
    volumeMounts:
    - name: bin-dir
      mountPath: /opt/bin

  # Main Container: Pipes output through PII-Shield
  containers:
  - name: my-application
    image: my-app:1.0
    # Override command to pipe stdout/stderr
    command: ["/bin/sh", "-c"]
    args: ["./start-my-app.sh 2>&1 | /opt/bin/pii-shield"]
    volumeMounts:
    - name: bin-dir
      mountPath: /opt/bin
    env:
      - name: PII_SALT
        # ⚠️ GENERATE A REAL RANDOM STRING HERE for production!
        # Or use: valueFrom: { secretKeyRef: { name: my-secret, key: pii-salt } }
        value: "change-me-to-random-string-for-prod"
```
