# @aragossa/pii-shield-wasi

High-performance PII redaction scanner powered by a core Go engine compiled to WebAssembly (WASI). It provides lightning-fast text analysis with hybrid heuristic and entropy-based validation.

## Installation

```bash
npm install @aragossa/pii-shield-wasi
```

## Usage

```javascript
const { PiiShield } = require('@aragossa/pii-shield-wasi');

// Initialize the scanner with optional configuration overrides
const shield = await PiiShield.create({
    entropyThreshold: 4.0,
    confidenceScore: 0.8
});

const text = "Connecting to DB with api_key: aB3$xyz890LmnopQ";
const redactedText = shield.redact(text);

console.log(redactedText);
// Output will have the high entropy token redacted
```

## Features

- **Blazing Fast**: Runs a highly optimized Go WASM binary in NodeJS natively.
- **Zero-Allocation**: Hot-paths have been optimized to prevent garbage collection overhead during large log streaming.
- **Hybrid Scoring**: Combines static whitelists, regex heuristics, and Shannon entropy for zero false-positives on things like UUIDs and IPv6 addresses.
