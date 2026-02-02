# Quick Start

## Running Locally (CLI)

You can test PII-Shield immediately using Docker. It reads from STDIN and writes to STDOUT.

### Step 1: Pull the image
```bash
docker pull thelisdeep/pii-shield:latest
```

### Step 2: Pipe logs through it
```bash
echo '{"level":"info", "msg":"Login attempt", "pass":"SuperSecret123"}' | \
docker run -i --rm thelisdeep/pii-shield:latest
```

**Output:**
```json
{"level":"info", "msg":"Login attempt", "pass":"[HIDDEN:5a1b2c]"}
```
