# PII-Shield Threat Model

## Scope

PII-Shield is an open-source security tool for redacting PII and secrets from logs before they leave an application runtime. The current scope covers:

- the Go scanner and CLI log-cleaning path;
- containerized sidecar usage;
- Kubernetes operator, webhook, policy, and Helm deployment paths;
- WASM SDK usage for in-process integrations;
- CI/CD and release artifacts that distribute binaries, containers, charts, and SDK packages.

Planned R&D areas such as production eBPF interception, Proxy-Wasm gateway integration, and hosted control-plane features are out of production security scope until explicitly marked stable.

## Security Assumptions

- Operators configure a persistent `PII_SALT` for production deployments when stable hashes are required.
- Custom redaction and safe-list rules are tested against representative logs before production rollout.
- Kubernetes clusters enforce namespace 
- isolation, RBAC, and secret access controls.
- CI/CD credentials are stored in GitHub Actions secrets or equivalent secret stores, not in the repository.
- Consumers review `KNOWN_LIMITATIONS.md` before relying on a deployment mode for compliance workloads.

## Protected Assets

- PII and sensitive text payloads in logs and documents.
- Application logs, traces, telemetry, and test fixtures.
- API keys, credentials, tokens, kubeconfigs, salts, and runtime secrets.
- Sanitized output and deterministic hash values.
- Scanner configuration, custom regex rules, safe-list rules, and Kubernetes `PiiPolicy` objects.
- CI/CD configuration, release credentials, build artifacts, and provenance metadata.
- Container images, Helm charts, Go modules, and Node/Python SDK packages.

## Actors

- Normal users and application owners who deploy or embed PII-Shield.
- Cluster administrators and maintainers who manage policies, charts, releases, and CI/CD.
- Malicious users who try to bypass redaction or extract sensitive data from logs.
- Attackers with network access to workloads, registries, CI systems, or package indexes.
- Compromised dependencies or build tools.
- Attackers with compromised repository, package registry, or CI credentials.

## Architecture And Data Flows

1. Application logs are produced by a workload or SDK caller.
2. Logs are passed through one of the supported integration paths:
   - CLI/container stdin-to-stdout filtering;
   - Kubernetes sidecar log file filtering;
   - operator-managed sidecar injection based on pod labels and `PiiPolicy`;
   - in-process WASM SDK calls.
3. The scanner applies static sensitive-key matching, custom regex redaction, safe-list rules, entropy detection, and deterministic HMAC-style hashing.
4. Sanitized output is emitted to downstream logging systems or returned to the embedding application.
5. CI/CD builds and publishes release artifacts including binaries, images, Helm charts, and SDK packages.

## Trust Boundaries

- User application to PII-Shield sidecar or SDK boundary.
- Pod/container boundary between application containers and injected sidecars.
- Kubernetes API boundary for admission webhooks, CRDs, RBAC, and `PiiPolicy` resources.
- Runtime secret boundary for `PII_SALT`, registry credentials, and deployment secrets.
- CI/CD boundary between repository code, GitHub Actions, package registries, and artifact consumers.
- Package dependency boundary between trusted project code and third-party modules/actions/images.

## STRIDE Threats And Mitigations

### Spoofing

Threats:

- A malicious workload impersonates an approved workload by applying injection labels or policy annotations.
- A compromised release or package registry identity publishes unofficial artifacts.
- CI/CD jobs run with broader credentials than required.

Mitigations:

- Require Kubernetes RBAC controls around policy creation and namespace changes.
- Publish official images, charts, and SDKs from documented registries only.
- Keep GitHub Actions permissions scoped per workflow where possible.
- Use protected branches, reviewed releases, and signed/provenance-backed artifacts as supply-chain maturity improves.

### Tampering

Threats:

- Attackers modify redaction rules to allow sensitive data through.
- Dependencies, GitHub Actions, Docker base images, Helm charts, or SDK packages are tampered with.
- Malicious input exploits parser edge cases to alter scanner behavior.

Mitigations:

- Review policy and configuration changes before production rollout.
- Enable Dependabot for Go, GitHub Actions, Docker, Node, and Python ecosystems.
- Run CI with unit tests, fuzz sanity checks, race tests, coverage checks, Helm runtime verification, and multi-arch image build verification.
- Keep fuzz and regression tests for malformed, nested, binary, multilingual, and structured log inputs.

### Repudiation

Threats:

- Maintainers or operators cannot prove which policy or release produced a redaction result.
- Security incidents lack enough context to trace configuration or release state.

Mitigations:

- Track releases with tags and published artifacts.
- Keep configuration in version-controlled manifests where possible.
- Use deterministic hashing with a persistent `PII_SALT` when correlation is required.
- Document limitations and deployment-specific validation results.

### Information Disclosure

Threats:

- PII or credentials pass through because of false negatives, unsupported log formats, weak configuration, or safe-list misuse.
- Secrets are committed to the repository or exposed through CI logs.
- Missing persistent salt breaks correlation or causes unexpected hash behavior after restart.
- Logs or test fixtures contain real user data.

Mitigations:

- Maintain conservative defaults for sensitive key detection and entropy checks.
- Support custom regex redaction for organization-specific identifiers.
- Support safe-list rules, but require production validation before use.
- Document secret-handling expectations in `SECURITY.md`.
- Run local tracked-file checks for common secret patterns before release work.
- Require persistent `PII_SALT` for production deployments that need stable hashes.

### Denial Of Service

Threats:

- Extremely large, deeply nested, malformed, or high-volume logs exhaust CPU or memory.
- Webhook or sidecar failure blocks application deployment or log processing.
- Dependency or registry outages prevent installation or upgrades.

Mitigations:

- Keep scanner hot paths optimized and covered by performance tests and benchmarks.
- Use recursion safeguards for deeply nested JSON.
- Validate Helm runtime behavior and multi-arch image builds in CI.
- Document Kubernetes logging and operator limitations in `KNOWN_LIMITATIONS.md`.
- Test webhook failure policy and deployment mode behavior before production rollout.

### Elevation Of Privilege

Threats:

- Operator, webhook, or sidecar permissions are broader than needed.
- CI/CD tokens or package publishing credentials allow unauthorized release actions.
- Compromised dependencies run code in privileged build or cluster contexts.

Mitigations:

- Use Kubernetes RBAC and namespace scoping for operator deployments.
- Keep CI workflow permissions minimal and explicit for release and publishing jobs.
- Use GitHub Actions secrets and package registry credentials only in workflows that need them.
- Review dependency updates and release workflow changes carefully.

## Residual Risks

- Full transparent interception of Kubernetes `stdout` and `stderr` logs is not complete.
- Pipe mode changes the target container command and must be tested per workload.
- The Kubernetes operator is in stabilization.
- eBPF interception, Proxy-Wasm gateway integration, and hosted control-plane features are R&D until marked stable.
- Redaction is probabilistic for some high-entropy and context-sensitive cases; custom rules and representative validation remain necessary.
- Safe-list rules can create false negatives if configured too broadly.

## Maintenance

Update this threat model when:

- a new deployment mode becomes production-supported;
- scanner detection behavior, redaction order, or hashing behavior changes;
- Kubernetes operator permissions, webhook behavior, or policy semantics change;
- CI/CD release, signing, provenance, or package publishing flows change;
- a security issue reveals a new threat, mitigation, or residual risk.
