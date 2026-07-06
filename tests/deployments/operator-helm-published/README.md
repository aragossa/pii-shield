# Operator Helm published deployment test

Installs the published `pii-shield/pii-shield-operator` chart with Helm-generated self-signed webhook certificates, then runs the shared access-log replay workload.

```bash
tests/deployments/operator-helm-published/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/operator-helm-published`.

Chart operations:

```bash
tests/deployments/operator-helm-published/chart.sh template
tests/deployments/operator-helm-published/chart.sh lint
tests/deployments/operator-helm-published/chart.sh upgrade
tests/deployments/operator-helm-published/chart.sh status
tests/deployments/operator-helm-published/chart.sh history
tests/deployments/operator-helm-published/chart.sh values
tests/deployments/operator-helm-published/chart.sh manifest
tests/deployments/operator-helm-published/chart.sh rollback
tests/deployments/operator-helm-published/chart.sh uninstall
```

What each command does:

| Command | What it does | When to use |
| --- | --- | --- |
| `template` | Renders the published `pii-shield/pii-shield-operator` chart to YAML without touching the cluster. | Check generated manifests, CRDs, webhook, RBAC, image tags, and values before install. |
| `lint` | Runs Helm chart validation against the published chart. | Catch chart syntax/schema issues before installing. |
| `upgrade` | Runs `helm upgrade --install` for release `pii-shield-operator` in namespace `operator-system`. | Install the published operator chart or apply chart/value changes. |
| `status` | Shows Helm release status. | Confirm the release is deployed and see revision/app metadata. |
| `history` | Shows Helm release revision history. | Decide which revision can be rolled back to. |
| `values` | Shows the effective Helm values for the deployed release. | Confirm which values are actually active in the cluster. |
| `manifest` | Shows the manifest stored in the deployed Helm release. | Compare the installed manifest with a fresh `template` render. |
| `rollback` | Rolls back the release, optionally to `REVISION=<n>`. | Revert a bad upgrade. |
| `uninstall` | Removes the Helm release from `operator-system`. | Clean up the operator chart install. |

Examples:

```bash
tests/deployments/operator-helm-published/chart.sh template > /tmp/pii-shield-operator.yaml

EXTRA_HELM_ARGS='--set webhook.failurePolicy=Fail' \
  tests/deployments/operator-helm-published/chart.sh upgrade

tests/deployments/operator-helm-published/chart.sh history

REVISION=1 tests/deployments/operator-helm-published/chart.sh rollback
```

Use `VALUES_FILE=...` or `EXTRA_HELM_ARGS='--set key=value'` to override chart values.

Prometheus metrics:

```bash
kubectl create serviceaccount pii-metrics-reader -n operator-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create clusterrolebinding pii-metrics-reader \
  --clusterrole=pii-shield-operator-metrics-reader \
  --serviceaccount=operator-system:pii-metrics-reader \
  --dry-run=client -o yaml | kubectl apply -f -

TOKEN="$(kubectl create token pii-metrics-reader -n operator-system)"
kubectl port-forward -n operator-system svc/pii-shield-operator-metrics-service 8443:8443 &
PF_PID=$!
sleep 2
curl -k -H "Authorization: Bearer ${TOKEN}" https://127.0.0.1:8443/metrics | grep -E 'controller_runtime|workqueue|process'
kill "${PF_PID}"
```

Cleanup:

```bash
tests/deployments/operator-helm-published/cleanup.sh
```
