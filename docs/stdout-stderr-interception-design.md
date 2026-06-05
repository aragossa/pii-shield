# Kubernetes stdout/stderr Interception Design

This document defines the design direction for production-grade Kubernetes `stdout` and `stderr` interception.

Current production-supported sidecar file mode requires the application to write logs to a configured file path. Full transparent interception of normal Kubernetes container logs is not production-supported yet.

## Goal

Support ordinary Kubernetes application logs without requiring application code changes or a special application-managed log file.

The production target is:

- application keeps writing to `stdout` and `stderr`;
- PII-Shield sanitizes logs before they reach downstream collectors;
- the deployment has explicit failure, rollback, and monitoring behavior;
- log loss, duplication, and ordering risks are tested and documented.

## Non-Goals

This design does not cover:

- eBPF interception;
- Proxy-Wasm gateway interception;
- hosted Control Plane behavior;
- model-assisted PII detection;
- replacing cluster log collectors.

## Candidate Approaches

| Approach | Summary | Pros | Risks |
| --- | --- | --- | --- |
| Command wrapper | Mutate container command to pipe app output through PII-Shield. | Works with normal stdout/stderr after wrapping. | Changes application command, brittle for complex entrypoints. |
| Shared file sidecar | Application writes to a shared file, sidecar emits sanitized stdout. | Current controlled rollout path. | Requires app logging path change. |
| Log collector plugin | Sanitize in Fluent Bit, Vector, Promtail, or collector pipeline. | Fits existing log pipeline. | Moves PII-Shield out of pod boundary; collector-specific integrations. |
| Runtime log file tailing | Tail kubelet/container runtime log files. | Keeps app unchanged. | Requires hostPath access, runtime-specific behavior, high security risk. |
| eBPF | Intercept writes at syscall/socket level. | Potentially transparent. | Experimental and not production-ready. |

## Recommended First Production Candidate

The first production candidate should be a **command wrapper mode** for selected workloads, not host log tailing.

Rationale:

- avoids hostPath access to node log directories;
- avoids runtime-specific kubelet log parsing as the first production path;
- can be rolled out workload by workload;
- can expose explicit fail-open/fail-closed behavior;
- can be tested without requiring node-level privileges.

Expected shape:

```text
original app command
  -> wrapper
  -> application stdout/stderr
  -> pii-shield sanitizer
  -> sanitized stdout/stderr
  -> normal Kubernetes logging
```

## Runtime And Logging Paths To Validate First

Start with:

- Kubernetes 1.28+;
- containerd;
- ordinary pod `stdout`;
- ordinary pod `stderr`;
- single-container workloads;
- low-to-medium log volume;
- workloads with simple command/args.

Defer:

- CRI-O;
- init-container heavy workloads;
- shell-heavy entrypoints;
- workloads that rely on signal handling quirks;
- very high-volume logs;
- node-level runtime log file interception.

## Failure Behavior To Define

The implementation must define:

- what happens when the sanitizer exits;
- what happens when the application exits;
- signal propagation from Kubernetes to the application;
- exit code propagation;
- stdout and stderr stream separation or merge behavior;
- behavior for very large lines;
- behavior under sanitizer backpressure;
- fail-open and fail-closed behavior;
- how unsanitized bypass is prevented or detected.

## Test Plan

Unit and integration tests should cover:

- ordinary stdout redaction;
- ordinary stderr redaction;
- mixed stdout and stderr;
- multiline logs;
- long lines;
- application exit code propagation;
- SIGTERM handling;
- sanitizer crash behavior;
- app crash behavior;
- high log volume;
- downstream collector receives sanitized logs only.

Kubernetes tests should cover:

- pod restart;
- sidecar or wrapper restart behavior;
- log collector ingestion;
- deployment rollout;
- rollback to original command;
- opt-out label or policy behavior.

## Rollout Plan

1. Implement wrapper mode behind an explicit policy option.
2. Keep file mode as the default controlled rollout path.
3. Enable wrapper mode only for one namespace and one workload.
4. Validate logs and alerts.
5. Expand by workload class.
6. Document unsupported entrypoint patterns.
7. Decide whether wrapper mode is production-ready before considering host log tailing.

## Open Engineering Tasks

- [ ] Define wrapper command contract.
- [ ] Preserve app signal handling.
- [ ] Preserve app exit code.
- [ ] Decide stdout/stderr merge or separation behavior.
- [ ] Add policy/config shape for wrapper mode.
- [ ] Add operator mutation support.
- [ ] Add CLI wrapper support.
- [ ] Add Kubernetes integration tests.
- [ ] Add collector validation tests.
- [ ] Document unsupported command patterns.
