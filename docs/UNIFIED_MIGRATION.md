# KernelGuard Repository Structure

The repository has one active implementation: `kernelguard/`. This directory is the KernelGuard Core and contains the controller, eBPF-LSM source, policies, agent example, event reader, tests and build instructions.

## Active source of truth

- `kernelguard/kgctl.py` — Zero Trust controller and workload lifecycle.
- `kernelguard/bpf/` — eBPF-LSM program and shared definitions.
- `kernelguard/policy/` — administrator-owned YAML policies.
- `kernelguard/agent/` — agent integration example.
- `kernelguard/tools/` — event reader and policy linter.
- `kernelguard/tests/` — controller tests and controlled probes.
- `kernelguard/Makefile` — BPF and userspace build.

## Project scope

The current implementation is eBPF-LSM + cgroup-v2 workload identity + administrator-defined Zero Trust policy + ring-buffer telemetry.

Behavioural analysis, ML detection, datasets, model inference and ML-driven response are not implemented and are not included in the active source tree. They are future research possibilities only.

## Validation boundary

The reports under `evidence/stage-validation/` preserve selected results from the supplied Ubuntu VM. They do not establish universal attack coverage or guarantee that a clean checkout works on every kernel. Run the unit tests, build, BPF verifier/load/attach checks and controlled enforcement tests on the target VM before merging changes into the default branch.

## Safety

Use a disposable test VM for live BPF operations. Do not load or detach programs on a shared host without checking ownership of existing BPF programs, links and pins.
