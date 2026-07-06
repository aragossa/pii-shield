# Operator Kustomize deployment test

Dev-only path. Builds the operator image, deploys `operator/config/default` through `make deploy`, then runs access-log replay.

This path requires cert-manager. The `operator/config/default` Kustomize tree includes `operator/config/certmanager`, so Kubernetes must already know the `Certificate` and `Issuer` kinds before `make deploy` runs.

If the cert-manager CRDs are missing, `run.sh` installs cert-manager automatically (via the jetstack Helm chart) before deploying. Set `CERT_MANAGER_AUTO_INSTALL=false` to disable this and require a pre-installed cert-manager instead; `CERT_MANAGER_WAIT_TIMEOUT` (default `180s`) controls how long it waits for the webhook.

To check or install cert-manager manually:

```bash
kubectl get crd certificates.cert-manager.io issuers.cert-manager.io

helm repo add jetstack https://charts.jetstack.io
helm repo update jetstack
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true
kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=180s
```

```bash
tests/deployments/operator-kustomize/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/operator-kustomize`.

Prometheus metrics:

```bash
kubectl create serviceaccount pii-metrics-reader -n operator-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create clusterrolebinding pii-metrics-reader \
  --clusterrole=operator-metrics-reader \
  --serviceaccount=operator-system:pii-metrics-reader \
  --dry-run=client -o yaml | kubectl apply -f -

TOKEN="$(kubectl create token pii-metrics-reader -n operator-system)"
kubectl port-forward -n operator-system svc/operator-controller-manager-metrics-service 8443:8443 &
PF_PID=$!
sleep 2
curl -k -H "Authorization: Bearer ${TOKEN}" https://127.0.0.1:8443/metrics | grep -E 'controller_runtime|workqueue|process'
kill "${PF_PID}"
```

Cleanup:

```bash
tests/deployments/operator-kustomize/cleanup.sh
```
