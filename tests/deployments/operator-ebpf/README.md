# Operator eBPF mode mutation test

Experimental mode. This checks that the webhook mutates the pod into eBPF mode. It is not a production sanitizer validation.
No sanitizer Prometheus metrics expected; only operator manager metrics are available via the operator deployment.

Preflight:

```bash
kubectl config current-context
kind get clusters
kubectl get nodes
kubectl get pods -n operator-system
kubectl get crd piipolicies.core.pii-shield.io
```

If `kubectl config current-context` prints `kind-pii-shield-manual` but `kind get clusters` says `No kind clusters found`, the kubeconfig context is stale. There is no cluster to clean up; recreate it and reinstall the operator:

```bash
kind create cluster --name pii-shield-manual
kubectl config use-context kind-pii-shield-manual
kubectl get nodes

tests/deployments/operator-helm-local/chart.sh upgrade

kubectl get pods -n operator-system
kubectl get crd piipolicies.core.pii-shield.io
```

Run:

```bash
tests/deployments/operator-ebpf/run.sh
```

Cleanup:

```bash
tests/deployments/operator-ebpf/cleanup.sh
```
