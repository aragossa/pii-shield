# Release Notes Policy

PII-Shield releases should include human-readable notes that help users decide whether and how to upgrade.

Raw commit logs are not enough for user-facing releases. Each release note should summarize the practical impact of the change.

## Required Sections

Use the following sections when they apply:

- Highlights
- Security
- Breaking Changes
- Upgrade Notes
- Kubernetes / Helm Changes
- SDK Changes
- Known Limitations
- Verification

## Security Notes

Security-relevant releases should describe:

- whether the release fixes a vulnerability or hardening issue;
- whether users need to rotate secrets, salts, tokens, or credentials;
- whether deployment defaults changed;
- whether scanner behavior changed in a way that affects false positives or false negatives.

Do not disclose sensitive vulnerability details before a fix is available and affected users have had reasonable time to upgrade.

## Upgrade Notes

Upgrade notes should include:

- required configuration changes;
- changed environment variables or Helm values;
- changed CRD, webhook, or operator behavior;
- migration steps when a deployment mode changes;
- rollback guidance for risky changes.

## Verification Notes

Release notes should link to:

- `checksums.txt` for binary artifacts;
- container image tags and, when available, digests;
- `docs/release-verification.md`;
- any SBOM, signature, or provenance artifacts published for that release.
