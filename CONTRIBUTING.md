# Contributing Guide

Welcome! Please read this short guide before you start.

## Prerequisites
You will need the following tools:
- **Go** (version 1.22+)
- **Minikube** or **Kind**
- **Helm**

## Local Setup
Run these commands to build the project locally and check for errors:
```bash
go mod tidy
go build -o bin/operator ./operator/main.go
# Or use the build script:
./build.sh
```

## Testing
Before making a PR, please run tests to make sure you didn't break the pipeline:
```bash
# Run unit and fuzzing tests
go test ./... -v -fuzz=Fuzz

# Run stress and smoke tests
./scripts/test-smoke.sh
```

For performance-sensitive changes, compare CLI throughput against the baseline branch:
```bash
BASE_REF=origin/main RUNS=7 LINES=500000 ./benchmark/run_benchmarks.sh
```

For scanner-only microbenchmarks, run:
```bash
go test -bench=. -benchmem ./pkg/scanner
```

## Review Policy
Pull requests should pass the required GitHub Actions checks before merge. Ownership for major areas of the repository is documented in `.github/CODEOWNERS`; use it to identify the right reviewer for scanner, operator, chart, SDK, workflow, and security-documentation changes.

For solo-maintainer periods, CODEOWNERS documents responsibility but should not be enforced as a required branch rule unless another reviewer is available.

## Operator Run
To debug the webhook in a local Minikube cluster:
```bash
# 1. Start cluster and use minikube docker daemon
minikube start
eval $(minikube docker-env)

# 2. Build local image
docker build -t pii-shield:local .

# 3. Install the Helm chart
helm upgrade --install pii-shield ./charts/pii-shield \
  --set image.repository=pii-shield \
  --set image.tag=local \
  --set demo.enabled=true \
  --namespace pii-shield --create-namespace
```
