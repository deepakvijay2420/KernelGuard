# KernelGuard Core

This directory contains the active KernelGuard implementation. It combines eBPF-LSM enforcement, cgroup-v2 workload identity, the Zero Trust controller, administrator policies, event telemetry and controlled tests.

## Components

- `kgctl.py` — validates policy, loads BPF programs, updates maps, manages cgroups and controls workload lifecycle.
- `bpf/` — BPF-LSM hooks and shared kernel/userspace structures.
- `policy/` — administrator-owned YAML policies.
- `agent/` — example Agentic AI integration.
- `tools/kg_events.c` — reads events from the BPF ring buffer.
- `tools/policy_lint.py` — validates policy files.
- `tests/` — controller unit tests, dry-run checks and controlled probes.
- `systemd/` — optional service unit.
- `Makefile` — builds the BPF object and event reader.

## Requirements

- Linux kernel with BPF-LSM and BTF support.
- cgroup v2 and bpffs.
- clang/LLVM with BPF target, GCC, libbpf development headers and bpftool.
- Python 3 and PyYAML.

The optional LangChain/Gemini agent requires its corresponding Python packages and a user-provided API key. The key must never be committed to the repository.

## Safe setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install PyYAML

python3 kgctl.py plan -p policy/policy.example.yaml
python3 -m unittest discover -s tests -v
make
sudo python3 kgctl.py doctor
```

Run commands from this directory. A successful policy plan, unit test or compilation does not by itself prove that BPF programs load and enforce policy on the target kernel.

## Runtime flow

1. The administrator prepares a YAML policy.
2. The controller validates the policy and prepares the BPF map entries.
3. The controller loads and attaches the BPF-LSM programs.
4. The controller creates a cgroup-v2 workload and registers its cgroup identity.
5. The managed agent runs with reduced privileges and configured resource limits.
6. BPF-LSM hooks check selected executable, file and network operations against policy.
7. Events are sent through the BPF ring buffer and read by the user-space event reader.

## Implemented security controls

- Executable allow-list checks using executable file identity.
- Configured sensitive filename rules that can deny access or taint a workload.
- IPv4 destination and port checks for tainted workloads.
- Selected BPF and ptrace operation restrictions.
- Audit and enforce policy modes.
- cgroup-v2 workload identity and lifecycle management.
- Structured event telemetry.

## Not implemented

Behavioural analysis, ML detection, dataset-driven classification, model inference and ML-driven response are future scope only. They are not part of this Core implementation.

## Safety

Use a disposable Ubuntu VM for live BPF loading and enforcement. Inspect existing BPF programs, links and pins before loading or unloading KernelGuard. Never test against production workloads or real credentials.
