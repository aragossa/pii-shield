# Standalone local Helm chart deployment test

Installs `charts/pii-shield` from the current checkout in demo mode and streams `notes/log_example/access.log` into the demo writer.

```bash
tests/deployments/standalone-helm-local/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/standalone-helm-local`.

Chart operations:

```bash
tests/deployments/standalone-helm-local/chart.sh template
tests/deployments/standalone-helm-local/chart.sh lint
tests/deployments/standalone-helm-local/chart.sh upgrade
tests/deployments/standalone-helm-local/chart.sh status
tests/deployments/standalone-helm-local/chart.sh history
tests/deployments/standalone-helm-local/chart.sh values
tests/deployments/standalone-helm-local/chart.sh manifest
tests/deployments/standalone-helm-local/chart.sh rollback
tests/deployments/standalone-helm-local/chart.sh uninstall
```

What each command does:

| Command | What it does | When to use |
| --- | --- | --- |
| `template` | Renders the local `charts/pii-shield` chart in demo mode to YAML without touching the cluster. | Check generated deployment, volumes, config, metrics, and demo resources before install. |
| `lint` | Runs Helm chart validation against the local standalone chart. | Catch chart syntax/schema issues before installing. |
| `upgrade` | Runs `helm upgrade --install` for release `pii-shield-demo` in namespace `pii-shield-demo`. | Install the local standalone chart or apply chart/value changes. |
| `status` | Shows Helm release status. | Confirm the release is deployed and see revision/app metadata. |
| `history` | Shows Helm release revision history. | Decide which revision can be rolled back to. |
| `values` | Shows the effective Helm values for the deployed release. | Confirm which values are actually active in the cluster. |
| `manifest` | Shows the manifest stored in the deployed Helm release. | Compare the installed manifest with a fresh `template` render. |
| `rollback` | Rolls back the release, optionally to `REVISION=<n>`. | Revert a bad upgrade. |
| `uninstall` | Removes the Helm release from `pii-shield-demo`. | Clean up the standalone chart install. |

Examples:

```bash
tests/deployments/standalone-helm-local/chart.sh template > /tmp/pii-shield-standalone-local.yaml

EXTRA_HELM_ARGS='--set demo.enabled=true --set metrics.enabled=true' \
  tests/deployments/standalone-helm-local/chart.sh upgrade

tests/deployments/standalone-helm-local/chart.sh history

REVISION=1 tests/deployments/standalone-helm-local/chart.sh rollback
```

Use `VALUES_FILE=...` or `EXTRA_HELM_ARGS='--set key=value'` to override chart values.

Prometheus metrics:

```bash
POD="$(kubectl get pod -n pii-shield-demo -l app.kubernetes.io/name=pii-shield -o jsonpath='{.items[0].metadata.name}')"
kubectl port-forward -n pii-shield-demo "pod/${POD}" 9090:9090 &
PF_PID=$!
sleep 2
curl -s http://127.0.0.1:9090/metrics | grep pii
kill "${PF_PID}"
```

Cleanup:

```bash
tests/deployments/standalone-helm-local/cleanup.sh
```
