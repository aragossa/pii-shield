# Scripts

## Test runners (from fast to thorough)

| Script | What it runs | Needs |
| --- | --- | --- |
| `test-unit.sh` | Unit tests of the root module and the operator | Go |
| `test-operator-integration.sh` | Operator integration tests against envtest (local kube-apiserver) | Go, envtest |
| `test-smoke.sh` | End-to-end smoke run of the scanner binary with performance metrics | Go, python3 |
| `test-deployments.sh [group\|path ...]` | Deployment test matrix (`tests/deployments/*`); groups: `local`, `published`, `cluster`, `cluster-published`, `all` | Docker; kind for cluster groups |
| `test-all.sh [deployment-group]` | Everything above, in order | All of the above |

Fixture for `test-deployments.sh`: set `PII_SHIELD_ACCESS_LOG` to a real log
(never commit or upload one), or let the script generate a synthetic fixture
via `generate-access-log-fixture.sh` — the default in CI.

## Utilities

| Script | Purpose |
| --- | --- |
| `generate-access-log-fixture.sh [out] [lines]` | Synthetic access.log-style fixture with fake PII (safe for CI) |
| `set-version.sh` | Bump project versions for a release |
| `verify-agent-multiarch-build.sh` | Check the agent image builds for all target architectures |
| `verify-helm-runtime.sh` | Validate Helm chart runtime behavior |
