# Operator pipe mode test

Assumes the operator is already installed. Creates a `pipe` mode policy and streams `notes/log_example/access.log` through the injected FIFO.

```bash
tests/deployments/operator-pipe/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/operator-pipe`.

Cleanup:

```bash
tests/deployments/operator-pipe/cleanup.sh
```
