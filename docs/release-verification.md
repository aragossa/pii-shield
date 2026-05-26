# Release Verification

This document explains how users can verify official PII-Shield release artifacts.

PII-Shield is in a production-hardening phase. Current releases publish checksums for binary artifacts. Release workflows are being hardened to publish container SBOM/provenance attestations and GitHub artifact attestations on new releases.

## Official Release Channels

Use only the official release channels documented in the repository:

- GitHub Releases for CLI binaries and checksums.
- GitHub Container Registry for container images under `ghcr.io/pii-shield/`.
- Docker Hub images under `thelisdeep/`.
- Helm chart releases from the documented PII-Shield Helm repository.
- npm and PyPI packages documented in the SDK READMEs.

## Verify GitHub Release Checksums

Download the release archive and `checksums.txt` from the same GitHub release.

```bash
sha256sum --check checksums.txt
```

On macOS, use:

```bash
shasum -a 256 --check checksums.txt
```

Only run binaries that match the published checksum.

## Verify Container Image Identity

Prefer immutable image digests in production manifests instead of mutable tags.

```bash
docker buildx imagetools inspect ghcr.io/pii-shield/pii-shield:<version>
docker buildx imagetools inspect ghcr.io/pii-shield/pii-shield-agent:<version>
docker buildx imagetools inspect ghcr.io/pii-shield/pii-shield-operator:<version>
```

Record the digest used in production change records or deployment manifests.

## SBOM And Vulnerability Scan Artifacts

The repository security scan workflow generates an SPDX JSON SBOM artifact for repository-level review. The container publishing workflow requests BuildKit SBOM and provenance attestations for pushed images.

Users with stricter supply-chain requirements should run their own image and dependency scans before promotion:

```bash
trivy image ghcr.io/pii-shield/pii-shield:<version>
trivy image ghcr.io/pii-shield/pii-shield-agent:<version>
trivy image ghcr.io/pii-shield/pii-shield-operator:<version>
```

## Provenance

For new releases that publish GitHub artifact attestations, verify artifacts with:

```bash
gh attestation verify <artifact> --repo pii-shield/pii-shield
```

For container images, prefer digest-pinned deployments and inspect registry attestations where supported by your registry tooling.

## Still Being Hardened

The following verification features are not yet complete release guarantees across every artifact type:

- cosign signatures for container image digests;
- npm or PyPI provenance verification.

These items are tracked in the supply-chain hardening roadmap.
