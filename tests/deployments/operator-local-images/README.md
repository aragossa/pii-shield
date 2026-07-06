# Operator local images deployment test

Builds local operator and agent images, loads them into the active Kind/Minikube cluster, installs the local operator chart with those images, then runs access-log replay.

```bash
tests/deployments/operator-local-images/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/operator-local-images`.

Chart operations:

```bash
IMAGE_TAG=manual tests/deployments/operator-local-images/chart.sh template
IMAGE_TAG=manual tests/deployments/operator-local-images/chart.sh lint
IMAGE_TAG=manual tests/deployments/operator-local-images/chart.sh upgrade
tests/deployments/operator-local-images/chart.sh status
tests/deployments/operator-local-images/chart.sh history
tests/deployments/operator-local-images/chart.sh values
tests/deployments/operator-local-images/chart.sh manifest
tests/deployments/operator-local-images/chart.sh rollback
tests/deployments/operator-local-images/chart.sh uninstall
```

What each command does:

| Command | What it does | When to use |
| --- | --- | --- |
| `template` | Renders the local `charts/pii-shield-operator` chart with local image overrides to YAML without touching the cluster. | Check generated manifests, CRDs, webhook, RBAC, image tags, and values before install. |
| `lint` | Runs Helm chart validation against the local operator chart. | Catch chart syntax/schema issues before installing. |
| `upgrade` | Runs `helm upgrade --install` for release `pii-shield-operator` in namespace `operator-system`. | Install the local chart with locally built images or apply chart/value changes. |
| `status` | Shows Helm release status. | Confirm the release is deployed and see revision/app metadata. |
| `history` | Shows Helm release revision history. | Decide which revision can be rolled back to. |
| `values` | Shows the effective Helm values for the deployed release. | Confirm which image tags and values are actually active in the cluster. |
| `manifest` | Shows the manifest stored in the deployed Helm release. | Compare the installed manifest with a fresh `template` render. |
| `rollback` | Rolls back the release, optionally to `REVISION=<n>`. | Revert a bad upgrade. |
| `uninstall` | Removes the Helm release from `operator-system`. | Clean up the operator chart install. |

Examples:

```bash
IMAGE_TAG=manual tests/deployments/operator-local-images/chart.sh template > /tmp/pii-shield-operator-local-images.yaml

IMAGE_TAG=manual EXTRA_HELM_ARGS='--set webhook.failurePolicy=Fail' \
  tests/deployments/operator-local-images/chart.sh upgrade

tests/deployments/operator-local-images/chart.sh history

REVISION=1 tests/deployments/operator-local-images/chart.sh rollback
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
tests/deployments/operator-local-images/cleanup.sh
```
