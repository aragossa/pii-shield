# PII-Shield Operator

The Kubernetes Operator for [PII-Shield](https://github.com/pii-shield/pii-shield), providing automatic Personally Identifiable Information masking for application logs in K8s clusters using Distroless Native Sidecars.

## Architecture

* **Operator Manager**: A lightweight Go controller managing `PiiPolicy` Custom Resources and a Mutating Webhook.
* **Sidecar Agent**: A highly-secure, distroless Go binary injected automatically into your Pods. It monitors application logs via `nxadm/tail` and masks PII in real time before streaming them to `stdout`.

## Getting Started

### Installation via Helm (Recommended)

The easiest way to install the operator is via our official Helm chart hosted on GitHub Pages.

1. Add the Helm repository:
   ```bash
   helm repo add pii-shield https://pii-shield.github.io/pii-shield
   helm repo update
   ```

2. Install the Operator:
   ```bash
   helm install pii-shield-operator pii-shield/pii-shield-operator -n operator-system --create-namespace
   ```
   *Note: If `cert-manager` is not installed, the Helm chart will automatically generate and inject fallback self-signed TLS certificates for the Mutating Webhook.*

### Quickstart Example

Once installed, you can protect any application by applying a `PiiPolicy` and adding a label to your Pods.

1. **Create a Policy:**
   ```yaml
   apiVersion: core.pii-shield.io/v1alpha1
   kind: PiiPolicy
   metadata:
     name: strict-policy
     namespace: default
   spec:
     injectionMode: "file"
   ```

   Supported `injectionMode` values:

   | Mode | Status | Description |
   |------|--------|-------------|
   | `file` | Stable (default) | The sidecar tails a log file on a shared `emptyDir` volume. Recommended for production. |
   | `pipe` | **Experimental** | Rewrites the target container command through `/bin/sh -c` to redirect output into a named pipe. Can break distroless images (no shell), argument quoting, signal handling, and the app lifecycle. The webhook returns a warning on injection. Not recommended for production. |
   | `ebpf` | Experimental / R&D | Kernel-level interception prototype. Not production-ready. |

2. **Label your Application Pods:**
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: my-app
   spec:
     template:
       metadata:
         labels:
           pii-shield.io/inject: "true"
         annotations:
           pii-shield.io/policy: "strict-policy"
   ```
   *Tip: You can also label an entire namespace (`pii-shield.io/inject: "true"`) to automatically protect all Pods within it.*

The Operator will automatically inject the secure Sidecar Agent into your Pod, configuring it with the correct `fsGroup` to securely access `emptyDir` log volumes.

## Development

If you want to contribute to the Operator:

> [!NOTE]
> The Kustomize and `make deploy` paths in this directory are for local development, CRD generation, and manual validation of the operator source tree. For user-facing v2.x installs, use the Helm chart.

### Prerequisites
- Go version v1.24+
- Docker version 17.03+
- kubectl and access to a K8s cluster (e.g. Minikube)

### Local Testing

1. Install the CRDs into the cluster:
   ```bash
   make install
   ```
2. Run the controller locally (outside the cluster):
   ```bash
   make run
   ```

### Synchronizing CRDs to the Helm Chart

If you modify the API definitions (`api/v1alpha1/piipolicy_types.go`), regenerate the manifests and automatically sync them to the Helm chart:

```bash
make sync-helm
```

## License

Distributed under the Apache 2.0 License.
