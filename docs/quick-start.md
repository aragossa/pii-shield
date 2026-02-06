# Quick Start

You can run PII-Shield immediately using Docker or by downloading a pre-built binary. The tool reads from **STDIN** and writes sanitized logs to **STDOUT**.

## Option 1: Docker (Fastest)

Ideal for quick testing without installing anything on your host.

### 1. Pull the image
```bash
docker pull thelisdeep/pii-shield:latest
```
### 2. Pipe logs through it
```bash
echo '{"level":"info", "msg":"Login attempt", "pass":"SuperSecret123"}' | \
docker run -i --rm thelisdeep/pii-shield:latest
```

## Option 2: Standalone Binary (No Docker)
Ideal for local development or servers where Docker is not available. You can download the latest release for Linux, macOS, or Windows from the [Releases Page](https://github.com/aragossa/pii-shield/releases).

### Linux / macOS
```bash
# 1. Download the release (example for Linux AMD64)
wget https://github.com/aragossa/pii-shield/releases/download/v1.0.0/pii-shield_1.0.0_linux_amd64.tar.gz

# 2. Extract the archive
tar -xvf pii-shield_1.0.0_linux_amd64.tar.gz

# 3. Run it
echo "User password=secret123" | ./pii-shield
```
### Windows (PowerShell)
```powershell
echo "User password=secret123" | .\pii-shield.exe
```
## Option 3: Go Install
If you have Go installed on your machine:
```bash
go install github.com/aragossa/pii-shield@latest
pii-shield --help
```
### Expected Output
Regardless of how you run it, PII-Shield will output the sanitized log line immediately:
**Input**
```json
{"level":"info", "msg":"Login attempt", "pass":"SuperSecret123"}
```
**Output**
```json
{"level":"info", "msg":"Login attempt", "pass":"[HIDDEN:5a1b2c]"}
```
