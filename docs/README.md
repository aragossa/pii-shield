# What is PII-Shield? 🛡️

**PII-Shield** is an intelligent, high-performance, **Open Source (Apache 2.0)** log sanitization tool designed to prevent sensitive data leaks (GDPR, SOC2, PCI-DSS, HIPAA) in your application logs.

Unlike traditional regex-based filters that are slow and hard to maintain, PII-Shield uses **Entropy Analysis** and **Context Awareness** to detect secrets (API Keys, Passwords, Tokens) dynamically—even if they don't match a known pattern.

## Why PII-Shield?

- 🚀 **Zero-Code Integration**: Works as a pipe wrapper or sidecar. No need to change your application code.
- 🧠 **Entropy-Based Detection**: Catches unknown high-entropy secrets (like `sk-proj-xyz...`) automatically.
- 🔒 **JSON Integrity**: Guarantees valid JSON output. It parses structure, redacts values, and rebuilds the JSON without corrupting the log format.
- 🔍 **Deterministic Hashing**: Replaces secrets with unique hashes (e.g., `[HIDDEN:a1b2c]`). This allows developers to correlate errors (e.g., "Did this user fail with the same wrong password 5 times?") without revealing the actual password.
- ⚡ **High Performance**: Written in Go, optimized for low-latency stream processing.
