#!/bin/bash
set -e
set -o pipefail

# --- Configuration ---
OPERATOR_NAMESPACE="operator-system"
APP_NAMESPACE="default"
HELM_RELEASE="pii-shield-operator"
IMAGE_TAG="e2e-test-$(date +%s)"
OPERATOR_IMAGE="ghcr.io/pii-shield/pii-shield-operator:${IMAGE_TAG}"
AGENT_IMAGE="ghcr.io/pii-shield/pii-shield-agent:${IMAGE_TAG}"

echo "🚀 Starting PII-Shield Operator E2E Tests..."

# --- 1. Teardown & Trap ---
function cleanup {
  echo "🧹 Cleaning up resources..."
  helm uninstall ${HELM_RELEASE} -n ${OPERATOR_NAMESPACE} --ignore-not-found 2>/dev/null || true
  kubectl delete -f tests/test-job.yaml -n ${APP_NAMESPACE} --ignore-not-found 2>/dev/null || true
  kubectl delete piipolicy strict-policy -n ${APP_NAMESPACE} --ignore-not-found 2>/dev/null || true
  # Clean up dangling resources from 'make deploy' or Kustomize
  kubectl delete secret pii-shield-operator-webhook-server-cert -n ${OPERATOR_NAMESPACE} --ignore-not-found 2>/dev/null || true
  kubectl delete mutatingwebhookconfiguration pii-shield-operator-mutating-webhook-configuration operator-mutating-webhook-configuration --ignore-not-found 2>/dev/null || true
}

# Always clean up on exit (success or failure)
trap cleanup EXIT

# Clean up before start just in case
cleanup

# --- 2. Build & Load Image ---
echo "📦 Building operator image ${OPERATOR_IMAGE}..."
make docker-build IMG=${OPERATOR_IMAGE}

echo "📦 Building agent image ${AGENT_IMAGE}..."
cd .. && docker build -t ${AGENT_IMAGE} -f Dockerfile.agent . && cd operator

echo "🚢 Loading images into local cluster..."
if command -v minikube &> /dev/null && minikube status &> /dev/null; then
  minikube image load ${OPERATOR_IMAGE}
  minikube image load ${AGENT_IMAGE}
elif command -v kind &> /dev/null && kind get clusters &> /dev/null; then
  # Honor KIND_CLUSTER (set by `make test-e2e`) so images land in the cluster
  # that was provisioned; fall back to kind's default cluster when unset.
  KIND_NAME_ARGS=()
  [ -n "${KIND_CLUSTER:-}" ] && KIND_NAME_ARGS=(--name "${KIND_CLUSTER}")
  kind load docker-image "${KIND_NAME_ARGS[@]}" ${OPERATOR_IMAGE}
  kind load docker-image "${KIND_NAME_ARGS[@]}" ${AGENT_IMAGE}
else
  echo "⚠️ Warning: Neither minikube nor kind detected. Assuming images are available."
fi

# --- 3. Helm Deployment ---
echo "⚙️ Installing Helm Chart..."
helm upgrade --install ${HELM_RELEASE} ../charts/pii-shield-operator \
  -n ${OPERATOR_NAMESPACE} --create-namespace \
  --set image.repository="ghcr.io/pii-shield/pii-shield-operator" \
  --set image.tag="${IMAGE_TAG}" \
  --set sidecar.image.repository="ghcr.io/pii-shield/pii-shield-agent" \
  --set sidecar.image.tag="${IMAGE_TAG}" \
  --set webhook.useCertManager=false \
  --wait --timeout=120s

# --- 4. Apply PiiPolicy ---
echo "📜 Applying PiiPolicy..."
cat <<EOF | kubectl apply -f -
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: strict-policy
  namespace: ${APP_NAMESPACE}
spec:
  injectionMode: "file"
  logPath: "/var/log/app/log.txt"
EOF

# Wait a moment for webhook caches to sync
sleep 2

# --- 5. Deploy Workload ---
echo "🚀 Deploying test-job..."
kubectl apply -f tests/test-job.yaml -n ${APP_NAMESPACE}

# Wait for Job Pod to be created
echo "⏳ Waiting for the Job pod to be created..."
while [[ $(kubectl get pods -l job-name=test-job -n ${APP_NAMESPACE} -o jsonpath='{.items}') == "[]" ]]; do
  sleep 1
done

# Wait for Job Pod to be Ready
echo "⏳ Waiting for test-job Pod to become Ready..."
if ! kubectl wait --for=condition=ready pod -l job-name=test-job -n ${APP_NAMESPACE} --timeout=60s; then
  echo "❌ Error: Pod did not become ready. Debug info:"
  kubectl describe pod -l job-name=test-job -n ${APP_NAMESPACE}
  kubectl logs -l job-name=test-job -n ${APP_NAMESPACE} --all-containers
  exit 1
fi

# Quick failure check
if kubectl get pod -l job-name=test-job -n ${APP_NAMESPACE} -o jsonpath='{.items[0].status.phase}' | grep -q "Failed"; then
  echo "❌ Error: Pod finished with Failed status"
  kubectl describe pod -l job-name=test-job -n ${APP_NAMESPACE}
  exit 1
fi

# Wait for Job to Complete by checking Pod phase
echo "⏳ Waiting for test-job to Complete..."
if ! kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod -l job-name=test-job -n ${APP_NAMESPACE} --timeout=60s; then
  echo "❌ Error: Job did not complete. Debug info:"
  kubectl describe pod -l job-name=test-job -n ${APP_NAMESPACE}
  exit 1
fi

# --- 6. Verification (Polling Logs) ---
echo "🔎 Checking PII-Shield Sidecar logs for successful redaction..."
SUCCESS_HIDDEN=false
SUCCESS_SAFE=false

for i in {1..10}; do
  if kubectl logs -l job-name=test-job -c pii-shield-sidecar -n ${APP_NAMESPACE} | grep -q '"email": "\[HIDDEN:'; then
    SUCCESS_HIDDEN=true
  fi
  if kubectl logs -l job-name=test-job -c pii-shield-sidecar -n ${APP_NAMESPACE} | grep -q '"msg": "job started"'; then
    SUCCESS_SAFE=true
  fi

  if [ "$SUCCESS_HIDDEN" = true ] && [ "$SUCCESS_SAFE" = true ]; then
    echo "✅ Success: PII data was successfully masked and safe data preserved!"
    break
  fi
  sleep 2
done

if [ "$SUCCESS_HIDDEN" = false ]; then
  echo "❌ Error: PII data was NOT masked properly."
  echo "--- Sidecar Logs ---"
  kubectl logs -l job-name=test-job -c pii-shield-sidecar -n ${APP_NAMESPACE}
  exit 1
fi

if [ "$SUCCESS_SAFE" = false ]; then
  echo "❌ Error: False positive: safe data was modified or not found."
  echo "--- Sidecar Logs ---"
  kubectl logs -l job-name=test-job -c pii-shield-sidecar -n ${APP_NAMESPACE}
  exit 1
fi

# --- 7. Negative Path (Isolation) ---
echo "🛡️ Deploying dummy-pod to verify webhook isolation..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: dummy-pod
  namespace: ${APP_NAMESPACE}
spec:
  containers:
  - name: main-container
    image: busybox:1.36
    command: ["sleep", "30"]
EOF

echo "⏳ Waiting for dummy-pod to be created..."
while [[ $(kubectl get pods dummy-pod -n ${APP_NAMESPACE} -o jsonpath='{.status.phase}' 2>/dev/null) == "" ]]; do
  sleep 1
done

DUMMY_CONTAINER_COUNT=$(kubectl get pod dummy-pod -n ${APP_NAMESPACE} -o jsonpath='{.spec.containers[*].name} {.spec.initContainers[*].name}' | wc -w | tr -d ' ')
if [ "$DUMMY_CONTAINER_COUNT" -ne 1 ]; then
  echo "❌ Error: Negative Path failed! Webhook injected sidecar into dummy-pod without label!"
  kubectl describe pod dummy-pod -n ${APP_NAMESPACE}
  exit 1
else
  echo "✅ Success: Webhook correctly ignored dummy-pod without pii-shield.io/inject label."
fi
kubectl delete pod dummy-pod -n ${APP_NAMESPACE} --ignore-not-found 2>/dev/null || true

echo "🎉 All E2E Tests Passed Successfully!"
exit 0
