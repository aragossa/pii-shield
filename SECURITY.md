# Security Policy

PII-Shield is currently in a production-hardening phase. Please treat security-sensitive deployments as controlled rollouts and validate policies against representative logs before production use.

## Reporting Security Issues

Please report security issues privately to the maintainer at ilya.ploskovitov@pii-shield.com. Include the affected component, reproduction steps, expected behavior, and any relevant logs or policy snippets.

## Supported Versions

The `main` branch is the active development line. Tagged releases should be evaluated with the documented limitations in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Deployment Guidance

- Configure a persistent `PII_SALT` for production deployments.
- Test custom redaction and whitelist rules before rollout.
- Review Kubernetes webhook behavior and failure policy for your compliance requirements.
- Treat eBPF and advanced gateway interception modes as R&D until explicitly marked stable.
