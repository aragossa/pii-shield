# Local binary runtime test

Builds `cmd/cleaner` locally and runs it as a stdin/stdout sanitizer.

```bash
tests/deployments/local-binary/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/local-binary`.

During `run.sh`, Prometheus metrics are enabled by default on `127.0.0.1:9090`.

```bash
watch -n 2 "curl -s http://127.0.0.1:9090/metrics | grep -E 'piishield_processed_bytes_total|piishield_redaction_events_total|piishield_errors_total'"
```

Prometheus metrics:

```bash
mkdir -p /tmp/pii-shield-manual
touch /tmp/pii-shield-manual/output.log

PII_METRICS_ENABLED=true PII_METRICS_PORT=9090 \
  ./bin/pii-shield --watch-file /tmp/pii-shield-manual/output.log &
PII_PID=$!

echo '{"token":"abc123secretXYZ","msg":"hello"}' >> /tmp/pii-shield-manual/output.log
sleep 2
curl -s http://127.0.0.1:9090/metrics | grep pii
kill "${PII_PID}"
```
