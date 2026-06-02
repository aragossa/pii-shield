# Out-of-Grant Production Readiness Tasks

This file tracks production-readiness work that is not covered by the current NLnet, OpenSSF, or selective PII model grant plans.

Execution rule: implement each task as a separate commit. If a task is too large, split it into smaller commits that can be reviewed independently.

## 1. Production-Grade Transparent Kubernetes stdout/stderr Interception

Goal: support ordinary Kubernetes application logs without requiring applications to write to a special file path.

Tasks:

- [x] Design the interception model for normal Kubernetes `stdout` and `stderr` logs.
- [x] Define which runtime/logging paths are supported first.
- [ ] Implement a production path that works without rewriting application code.
- [ ] Validate behavior with common container runtime logging formats.
- [ ] Add tests for ordinary pod logs.
- [ ] Add tests for log rotation.
- [ ] Add tests for pod restart behavior.
- [ ] Add tests for sidecar crash behavior.
- [ ] Add tests for log loss and duplicate delivery risks.
- [x] Document limitations, supported environments, and rollback guidance.

Partially completed in `docs/stdout-stderr-interception-design.md`. The recommended first candidate is command wrapper mode for selected workloads. Production implementation and Kubernetes/runtime validation remain open.

Out of grant scope because NLnet covers Proxy-Wasm, eBPF R&D, and Control Plane work, while the OpenSSF grant covers hardening, documentation, testing, and supply-chain readiness. Neither plan promises full transparent Kubernetes `stdout`/`stderr` interception.

## 2. Operator Enterprise Stabilization

Goal: make the Kubernetes operator boring and predictable enough for enterprise production use.

Tasks:

- Define HA expectations for the operator controller.
- Validate reconciliation behavior during pod restarts and leader changes.
- Add upgrade safety tests for CRDs.
- Add rollback safety tests for CRDs and webhook configuration.
- Define and test admission webhook failure policy behavior.
- Validate cert lifecycle and renewal behavior.
- Add namespace-by-namespace rollout support or documented rollout procedure.
- Add canary rollout guidance for operator upgrades.
- Document operational risks and recovery steps.

Out of grant scope because the grant plans include operator integration testing and Control Plane UI work, but do not include a full enterprise operator stabilization track.

## 3. Production Failure-Mode Engineering For Sidecar Mode

Goal: define and test what happens when the sidecar path fails under real production pressure.

Tasks:

- [x] Define expected behavior when the sidecar process crashes.
- [x] Define backpressure behavior when the sanitizer is slower than log production.
- [x] Define behavior for very large log lines.
- [x] Define behavior for truncated lines.
- [x] Define behavior during file rotation.
- [x] Define behavior under disk pressure.
- [x] Add fail-open and fail-closed policy options, or document the chosen fixed behavior.
- [ ] Add tests for each failure mode.
- [x] Add operator and Helm configuration notes where runtime behavior is configurable.
- [x] Document production recommendations for each failure mode.

Partially completed in `docs/sidecar-failure-modes.md`, `CONFIGURATION.md`, and the `pii-shield` Helm chart. Buffer overflow fail-open and fail-closed behavior has focused tests. File rotation, sidecar restart, application restart, disk pressure, and downstream collector bypass checks still need integration or Kubernetes-level tests.

Out of grant scope because the grant plans cover testing and documentation broadly, but do not explicitly cover runtime reliability engineering for sidecar failure modes.

## 4. Kubernetes Compatibility Matrix

Goal: make supported Kubernetes environments explicit and testable.

Tasks:

- [x] Define the supported Kubernetes version range.
- [ ] Test against Kind.
- [ ] Test against Minikube.
- [ ] Test against K3s.
- [ ] Test against at least one managed Kubernetes service such as EKS, GKE, or AKS.
- [x] Record container runtime assumptions.
- [x] Record known incompatibilities.
- [x] Add a compatibility table to documentation.
- [x] Add a repeatable compatibility test checklist.

Partially completed as a compatibility matrix and repeatable validation checklist in `docs/kubernetes-compatibility.md`. The environment rows are documented as validation targets; individual cluster evidence should be filled in when each environment is actually tested.

Out of grant scope because the grant plans include operator tests, but not full multi-cluster compatibility certification.

## 5. Operational Runbooks And Alert Rules

Goal: make production operation repeatable when something goes wrong.

Tasks:

- [x] Write a runbook for admission webhook failures.
- [x] Write a runbook for sidecar injection failures.
- [x] Write a runbook for high false-positive incidents.
- [x] Write a runbook for high false-negative incidents.
- [x] Write a runbook for dependency/security alert response during production incidents.
- [x] Add Prometheus alert rules for webhook health.
- [x] Add Prometheus alert rules for injection failures.
- [x] Add Prometheus alert rules for sidecar crash or restart signals.
- [x] Add Prometheus alert rules for sanitizer error rates.
- [x] Document alert severity and suggested response time.

Completed in `docs/operational-runbooks.md` and `charts/pii-shield/templates/prometheusrule.yaml`.

Out of grant scope because NLnet covers Grafana and ELK visualization, but not incident runbooks or alert policy.

## 6. Production Adoption Checklist Per Deployment Mode

Goal: give users a clear adoption gate for each supported deployment mode.

Tasks:

- [x] Create a checklist for CLI/container use.
- [x] Create a checklist for sidecar file mode.
- [x] Create a checklist for Kubernetes operator mode.
- [x] Create a checklist for WASM SDK use.
- [x] Mark each deployment mode as ready, controlled rollout, beta, or experimental.
- [x] Define required configuration for each mode.
- [x] Define required validation before production rollout.
- [x] Define rollback steps for each mode.
- [x] Define monitoring requirements for each mode.
- [x] Document compliance-review questions for security teams.

Completed in `docs/production-adoption-checklist.md`.

Out of grant scope because the OpenSSF grant covers readiness documentation broadly, but does not include complete per-mode production adoption gates.
