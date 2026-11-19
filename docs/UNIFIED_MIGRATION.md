# KernelGuard source-of-truth and integration status

**Canonical active implementation:** `kernelguard/`  
**Current integration branch:** `integration/latest-core-controller`  
**Development snapshot reviewed:** Ubuntu VM archive supplied on 19 November 2026.

## Repository organisation

- `kernelguard/` — active runtime implementation: eBPF-LSM source, ZTA controller, policies, event reader, agent example and tests.
- `research/` — retained historical or exploratory materials only; behavioural analysis and ML are not implemented features of the current KernelGuard runtime.
- `evidence/` — preserved test logs, event records, benchmark outputs and evaluation reports.
- `docs/` — architecture, threat model, policy, review and demonstration documentation.
- `archive/` — historical agent, daemon, eBPF, policy and script snapshots retained for provenance.

The separate `KernelGuard-Core/` directory in the supplied development archive is a working migration copy, not a second canonical product. Its latest hardened `kgctl.py` has been synchronized into `kernelguard/kgctl.py` on this integration branch. Do not create a second active implementation tree in the published repository.

## What is implemented

### Runtime security

- eBPF-LSM hooks inspect selected executable, file-open, network, BPF and ptrace-related operations.
- A cgroup-v2 workload identity associates managed agent processes with administrator-defined agent IDs.
- YAML policies are validated and compiled into BPF map state by the userspace controller.
- Executable allow-list checks are scoped to the managed agent identity.
- Sensitive filename rules can deny a file open or mark the workload tainted.
- A tainted workload is subject to configured IPv4 egress allow-list checks.
- Audit mode records would-deny decisions; enforce mode rejects supported operations.
- Ring-buffer telemetry is emitted as structured JSON Lines.
- The controller drops the workload to a configured unprivileged user, clears supplementary groups, applies `NO_NEW_PRIVS`, and configures cgroup resource limits.
- The latest controller fails closed when required cgroup controllers or configured limit files cannot be verified. It also terminates remaining descendants and retains BPF identity/run state if it cannot verify that the cgroup is empty.

### Behavioural analysis and ML status

Behavioural analysis, ML-based detection, dataset-driven classification, model inference and ML-driven risk fusion are **future scope**. They are not implemented in the current KernelGuard runtime. Any historical datasets, scripts, models or saved results retained in the repository are preserved for provenance only; they must not be described as active, integrated or validated KernelGuard capabilities.

Potential future work may include collecting behavioural traces from the current event stream, defining and validating features, preparing reproducible datasets, evaluating models, and designing an out-of-band response workflow. These items become implementation claims only after code and repeatable tests exist.

## Verified evidence from the supplied Ubuntu VM

The supplied Stage 3 report records 30 controller unit tests passing, an allowed `whoami` operation, and audit-mode logging of an unapproved `id` execution. The supplied Stage 5 report records an enforce-mode synthetic `.env` taint event, denial of a synthetic file named `shadow`, and denial of a connection to `1.1.1.1:443` after taint. A separate enforcement report records allowed `whoami` and refused `/usr/bin/id` with `EPERM`.

These are finite tests from the supplied Ubuntu environment, not a claim that every hook, kernel version, attack family or workload is covered. The reports are preserved under `evidence/stage-validation/`.

## Required validation after checkout

1. Run Python unit tests and dry-run validation.
2. Build the BPF object and event reader on the target Ubuntu kernel.
3. Verify BPF-LSM availability, verifier acceptance, program load/attach and ring-buffer event delivery.
4. Re-run audit and enforce tests on the target VM and preserve exact outputs.
5. Exercise cgroup controller-unavailable, limit-write failure, child/descendant cleanup and cleanup-failure paths.
6. Re-run the guide demo from a clean checkout.

A successful unit test or BPF compilation alone does not prove runtime kernel enforcement.

## Future scope

1. Design and implement a behavioural event collection pipeline based on the current ring-buffer event format.
2. Define and validate workload behaviour features and reproducible labelled test scenarios.
3. Evaluate suitable anomaly-detection or classification methods with documented methodology.
4. If required, design an out-of-band risk assessment and operator-controlled response interface.

None of these ML/behavioural-analysis capabilities is part of the current implementation.

## Historical source and preservation policy

Do not delete `archive/`, prior agents, datasets, models, results or experiment traces merely because they are not part of the active runtime. Keep provenance and clearly label historical components. New active runtime changes belong under `kernelguard/`; future or historical research material belongs under `research/` and must be labelled as not implemented; test proof belongs under `evidence/`.
