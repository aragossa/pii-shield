# Operator Stabilization Guide

This guide defines the operator behavior that should be validated before broad enterprise production rollout.

PII-Shield operator mode is suitable for controlled rollouts. Treat broad multi-namespace adoption as a staged process with explicit rollback and monitoring.

## High Availability Expectations

The operator runs with leader election enabled. For higher availability:

- set `replicaCount` to at least `2`;
- enable `podDisruptionBudget.enabled=true`;
- keep `podDisruptionBudget.minAvailable=1`;
- spread replicas across nodes when cluster policy supports it;
- alert when the operator has no available replicas.

Example:

```yaml
replicaCount: 2
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

## Reconciliation Behavior

Expected behavior:

- The operator should keep watching `PiiPolicy` resources.
- New pods in enabled namespaces should be evaluated by the admission webhook.
- Existing pods are not automatically rewritten unless they are recreated.
- Policy changes affect future admissions and any controller behavior that explicitly reconciles policy state.

Validation checklist:

- [ ] Restart the operator leader and confirm another replica takes over.
- [ ] Create a `PiiPolicy` after an operator restart.
- [ ] Create a protected pod after an operator restart.
- [ ] Update a policy and recreate a protected pod.
- [ ] Confirm events and logs make reconciliation failures visible.

## Admission Webhook Failure Policy

`webhook.failurePolicy` controls what Kubernetes does when the webhook is unavailable.

| Value | Behavior | Use case |
| --- | --- | --- |
| `Ignore` | Pod creation continues if the webhook fails. Pods may run without injection. | Availability-first rollout and early adoption. |
| `Fail` | Pod creation fails if the webhook fails. | Compliance-sensitive enforcement after monitoring and rollback are ready. |

Default: `Ignore`.

Production recommendation:

- Start with `Ignore` during controlled rollout.
- Move to `Fail` only after webhook health alerts, runbooks, and emergency bypass procedures are tested.

## CRD Upgrade Safety

Before upgrading CRDs:

- [ ] Back up existing `PiiPolicy` resources.
- [ ] Confirm new CRD schema is backwards-compatible.
- [ ] Confirm conversion is not required, or document the conversion path.
- [ ] Run `helm template` for old and new chart versions.
- [ ] Apply changes in a staging namespace or staging cluster first.

Commands:

```bash
kubectl get piipolicy -A -o yaml > piipolicies-backup.yaml
helm template pii-shield-operator charts/pii-shield-operator > rendered-operator.yaml
```

## Rollback Safety

Rollback steps:

- [ ] Remove injection labels from affected namespaces or workloads if pod creation is blocked.
- [ ] Roll back the operator Helm release.
- [ ] Restore previous `PiiPolicy` resources if policy changes caused regression.
- [ ] Recreate affected pods only after confirming the desired injection behavior.
- [ ] Keep the previous sidecar image tag available.

Emergency bypass:

- Remove `pii-shield.io/injection: enabled` from the namespace.
- Remove `pii-shield.io/inject: "true"` from the workload.
- Set `webhook.failurePolicy=Ignore` if strict admission enforcement is blocking recovery.

## Certificate Lifecycle

When `webhook.useCertManager=true`, cert-manager manages webhook certificates.

Production checks:

- [ ] Confirm cert-manager is installed and healthy.
- [ ] Confirm the `Certificate` resource is ready.
- [ ] Confirm the webhook CA bundle is injected.
- [ ] Alert before webhook certificate expiry.
- [ ] Test certificate renewal in staging.

When `webhook.useCertManager=false`, Helm generates self-signed certificates during installation. Use this only for local validation or tightly controlled environments.

## Namespace Rollout And Canary

Recommended rollout:

1. Install the operator.
2. Enable injection only in a staging namespace.
3. Create a low-risk `PiiPolicy`.
4. Label one low-risk workload.
5. Validate sidecar injection and sanitized output.
6. Add monitoring and runbook links.
7. Expand namespace by namespace.
8. Move `webhook.failurePolicy` to `Fail` only if compliance requires it and recovery has been tested.

Canary checks:

- [ ] One namespace only.
- [ ] One workload only.
- [ ] Representative logs.
- [ ] Known false-positive and false-negative samples.
- [ ] Sidecar restart alert.
- [ ] Operator availability alert.
- [ ] Rollback exercise.

## Operational Risks

| Risk | Mitigation |
| --- | --- |
| Webhook unavailable | Alert on operator availability and webhook endpoints. Keep emergency bypass documented. |
| Incorrect policy | Roll out policy changes to one namespace first. Keep previous policy YAML. |
| Sidecar injection missing | Check labels, webhook events, and operator logs. |
| Cert expiry | Use cert-manager and expiry alerts. |
| CRD regression | Back up resources and test upgrades in staging. |
| Broad rollout blast radius | Use namespace-by-namespace adoption and canary workloads. |
