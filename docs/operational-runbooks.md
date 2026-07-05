# Operational Runbooks

Use these runbooks when PII-Shield is deployed in production or controlled production rollouts.

## Alert Severity

| Severity | Expected response | Examples |
| --- | --- | --- |
| Critical | Start investigation immediately. | Sanitized logs stop flowing for protected workloads. |
| Warning | Investigate during the current on-call window. | Error rate increases, sidecar restarts, latency increases. |
| Info | Review during normal maintenance. | Low-volume workloads with no recent redactions. |

## Admission Webhook Failures

Symptoms:

- New pods are not created.
- Pods are created without PII-Shield sidecars.
- Kubernetes events mention admission webhook timeouts or errors.

Immediate checks:

- [ ] Check operator pod health.
- [ ] Check admission webhook configuration.
- [ ] Check webhook service endpoints.
- [ ] Check TLS certificate validity.
- [ ] Check recent operator logs.
- [ ] Check namespace labels and pod labels.

Commands:

```bash
kubectl get pods -n operator-system
kubectl get validatingwebhookconfiguration,mutatingwebhookconfiguration
kubectl get events --all-namespaces --sort-by=.lastTimestamp
kubectl logs -n operator-system deploy/pii-shield-operator
```

Recovery:

- [ ] Restart the operator if it is unhealthy.
- [ ] Roll back the operator Helm release if the failure started after an upgrade.
- [ ] Remove injection labels from affected workloads if pod creation must continue.
- [ ] Disable the webhook only as an emergency action and record the exception.

## Sidecar Injection Failures

Symptoms:

- Pods with injection labels do not contain the PII-Shield sidecar.
- `PiiPolicy` changes do not affect new pods.
- Protected workloads produce unsanitized logs.

Immediate checks:

- [ ] Confirm the pod has `pii-shield.io/inject: "true"`.
- [ ] Confirm the namespace has the expected labels.
- [ ] Confirm the referenced `PiiPolicy` exists.
- [ ] Confirm the operator has permissions to read the policy.
- [ ] Check pod events for webhook patches or admission errors.

Commands:

```bash
kubectl describe pod <pod> -n <namespace>
kubectl get piipolicy -A
kubectl get events -n <namespace> --sort-by=.lastTimestamp
kubectl logs -n operator-system deploy/pii-shield-operator
```

Recovery:

- [ ] Fix labels or policy references.
- [ ] Recreate pods after policy or label fixes.
- [ ] Roll back the policy if the issue started after a policy update.
- [ ] Remove injection labels if the workload must run without PII-Shield during the incident.

## High False-Positive Incidents

Symptoms:

- Logs lose important debugging values.
- Safe identifiers are redacted.
- Teams report reduced observability after rollout.

Immediate checks:

- [ ] Identify the affected workload and log pattern.
- [ ] Check recent changes to `PII_ENTROPY_THRESHOLD`.
- [ ] Check recent changes to `PII_CUSTOM_REGEX_LIST`.
- [ ] Check recent changes to `PII_SAFE_REGEX_LIST`.
- [ ] Collect representative sanitized and original samples without exposing real PII.

Recovery:

- [ ] Add a narrow safe-list rule for known safe identifiers.
- [ ] Revert broad custom regex rules.
- [ ] Raise the entropy threshold only after testing representative logs.
- [ ] Roll back to previous policy or Helm values if observability is severely degraded.

Post-incident:

- [ ] Add regression fixtures for the false-positive pattern.
- [ ] Document the accepted safe-list rule and owner.
- [ ] Review whether the same pattern appears in other workloads.

## High False-Negative Incidents

Symptoms:

- Sensitive data appears in downstream logs.
- Security review finds unredacted PII or secrets.
- A new domain-specific identifier is not detected.

Immediate checks:

- [ ] Identify the data class that escaped redaction.
- [ ] Check whether the value is structured or free-form.
- [ ] Check whether a safe-list rule bypassed redaction.
- [ ] Check whether the log path bypassed PII-Shield.
- [ ] Check whether the affected workload was injected and running the expected policy.

Recovery:

- [ ] Add a custom regex rule for structured identifiers.
- [ ] Add sensitive key names for `key=value` patterns.
- [ ] Lower the entropy threshold only after testing representative logs.
- [ ] Remove or narrow unsafe safe-list rules.
- [ ] Rotate leaked credentials if secrets were exposed.

Post-incident:

- [ ] Add regression fixtures for the missed pattern.
- [ ] Review downstream retention and deletion requirements.
- [ ] Document the incident and remediation owner.

## Dependency Or Security Alert Response

Symptoms:

- Dependabot alert is opened.
- CodeQL alert is opened.
- OpenSSF Scorecard reports a vulnerability.
- `govulncheck` reports a reachable vulnerability.

Immediate checks:

- [ ] Identify affected module or package.
- [ ] Determine whether the vulnerable code is reachable.
- [ ] Check fixed version and compatibility notes.
- [ ] Check whether Dependabot already opened a PR.
- [ ] Check whether the finding affects released artifacts.

Recovery:

- [ ] Update the dependency.
- [ ] Run `go test ./...` in the root module.
- [ ] Run `cd operator && go test ./...`.
- [ ] Run `govulncheck ./...` in affected Go modules.
- [ ] Re-run Scorecard targeted checks after merge.
- [ ] Publish a security release if released artifacts are affected and the issue is material.

Response target:

- Critical reachable vulnerability: same day triage.
- High reachable vulnerability: triage within 2 business days.
- Medium reachable vulnerability: triage within 7 business days.
- Non-reachable or module-level finding: document and remediate in the next dependency update window.

## Prometheus Alerts

The Helm chart can render a `PrometheusRule` for Prometheus Operator installations:

```yaml
metrics:
  prometheusRule:
    enabled: true
```

The default rules cover:

- target availability;
- sidecar restarts through kube-state-metrics;
- sanitizer error rate;
- sanitizer processing latency;
- missing processed-log throughput.

Tune alert thresholds and labels in `values.yaml` before production rollout.

The operator Helm chart can also render operator and webhook alert rules:

```yaml
metrics:
  prometheusRule:
    enabled: true
```

The operator rules cover:

- operator deployment availability;
- webhook service endpoint availability;
- webhook certificate expiry when cert-manager metrics are available;
- injection or admission failures when Kubernetes event metrics such as `kube_event_count` are available.

These rules depend on common cluster observability components such as kube-state-metrics, cert-manager metrics, and an event metrics exporter. Disable or adjust rules that are not supported by your monitoring stack.
