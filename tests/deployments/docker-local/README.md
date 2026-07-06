# Docker local runtime test

Builds the local PII-Shield image and runs it as a stdin/stdout sanitizer.

```bash
tests/deployments/docker-local/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/docker-local`.

During `run.sh`, Prometheus metrics are enabled by default on `127.0.0.1:9090`.

```bash
watch -n 2 "curl -s http://127.0.0.1:9090/metrics | grep -E 'piishield_processed_bytes_total|piishield_redaction_events_total|piishield_errors_total'"
```

Use `PII_METRICS_HOST_PORT=9091` if local port `9090` is busy.

Prometheus metrics:

```bash
mkdir -p /tmp/pii-shield-manual
touch /tmp/pii-shield-manual/output.log

docker run -d --rm --name pii-shield-metrics \
  -p 9090:9090 \
  -v /tmp/pii-shield-manual:/var/log/app \
  -e PII_METRICS_ENABLED=true \
  -e PII_METRICS_PORT=9090 \
  pii-shield:manual \
  --watch-file /var/log/app/output.log

echo '{"token":"abc123secretXYZ","msg":"hello"}' >> /tmp/pii-shield-manual/output.log
sleep 2
curl -s http://127.0.0.1:9090/metrics | grep pii
docker stop pii-shield-metrics
```
