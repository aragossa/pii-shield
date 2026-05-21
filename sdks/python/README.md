# pii-shield-wasi

High-performance PII redaction scanner powered by a core Go engine compiled to WebAssembly (WASI). It provides lightning-fast text analysis with hybrid heuristic and entropy-based validation.

## Installation

```bash
pip install pii-shield-wasi
```

## Usage

```python
from pii_shield import PiiShield, PiiShieldConfig

# Initialize the scanner with optional configuration overrides
shield = PiiShield(PiiShieldConfig(
    entropy_threshold=4.0,
    confidence_score=0.8
))

text = "Connecting to DB with password: MySuperSecretPassword123!"
redacted_text = shield.redact(text)

print(redacted_text)
# Output might redact the high entropy secret based on context
```

## Features

- **Blazing Fast**: Runs a highly optimized Go WASM binary in a native V8/Wasmtime environment.
- **Zero-Allocation**: Hot-paths have been optimized to prevent garbage collection overhead during large log streaming.
- **Hybrid Scoring**: Combines static whitelists, regex heuristics, and Shannon entropy for zero false-positives on things like UUIDs and IPv6 addresses.
