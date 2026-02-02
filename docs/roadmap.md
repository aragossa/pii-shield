# Roadmap

We are actively developing PII-Shield. Here is what's coming next:

- **Helm Chart & K8s Controller**: Automatic injection of PII-Shield sidecars via MutatingAdmissionWebhook (No need to edit Deployment YAMLs manually).
- **Prometheus Metrics**: Native endpoint exposing `leaks_prevented_total` and latency metrics.
- **Global Whitelists**: Ability to explicitly allow specific low-entropy tokens.

## Contact & Support
Found a bug or have a feature request?

- **GitHub**: [github.com/aragossa/pii-shield](https://github.com/aragossa/pii-shield)
- **Docker**: [hub.docker.com/r/thelisdeep/pii-shield](https://hub.docker.com/r/thelisdeep/pii-shield)
