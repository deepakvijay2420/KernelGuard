# KernelGuard

**Linux runtime security for Agentic AI workloads using eBPF-LSM and Zero Trust Architecture (ZTA).**

KernelGuard is a research prototype that applies administrator-defined security policies to selected operating-system actions performed by a managed AI-agent workload.

The project focuses on controlling what an agent process can execute, which configured sensitive files it can access, and where a tainted workload can connect.

> **Scope:** The current implementation is the eBPF-LSM + cgroup-v2 + ZTA controller described below. Machine learning, behavioural analysis, datasets and model-based detection are not implemented and are not part of the current codebase.

## Implemented components

- **eBPF-LSM:** checks selected executable, file-open, network, BPF and ptrace operations.
- **cgroup v2 identity:** associates managed processes and their descendants with a registered workload identity.
- **ZTA controller:** validates administrator-owned YAML policy and updates BPF maps.
- **Executable control:** checks executable file identity against the configured allow-list.
- **Sensitive-file control:** applies configured filename rules to deny or taint a workload.
- **Network control:** applies configured IPv4 destination and port restrictions to a tainted workload.
- **Audit and enforce modes:** records policy decisions and, in enforce mode, rejects covered operations.
- **Event reader:** reads BPF ring-buffer events in user space.
- **Workload lifecycle controls:** applies privilege reduction, cgroup limits and managed workload response actions.

## Architecture

```text
Administrator YAML Policy
          |
          v
     kgctl.py (ZTA Controller)
          |
    +-----+------+
    |            |
    v            v
 cgroup v2     BPF Policy Maps
 identity          |
    |              |
    v              |
 Managed Agent     |
    |              |
    +--- OS action-+
          |
          v
      BPF-LSM Hooks
          |
     Policy Check
          |
    ALLOW / AUDIT / DENY
          |
          v
     BPF Ring Buffer
          |
          v
    kg_events Reader
```

The kernel enforces selected OS-level operations. It does not inspect prompt text, model reasoning or encrypted HTTPS request bodies. KernelGuard can restrict an unauthorised OS action caused by an agent; it does not claim semantic prompt-injection detection.

## Repository structure

```text
KernelGuard/
├── README.md
├── SECURITY.md
├── kernelguard/
│   ├── agent/       # Agent integration example
│   ├── bpf/         # eBPF-LSM source and shared definitions
│   ├── policy/      # Administrator YAML policies
│   ├── tests/       # Controller tests and controlled probes
│   ├── tools/       # Ring-buffer event reader and policy linter
│   ├── systemd/     # Optional service unit
│   ├── kgctl.py     # ZTA controller
│   ├── Makefile
│   └── README.md
├── docs/            # Current architecture and demo guide
└── evidence/        # Supplied Ubuntu validation reports
```

## Quick start

```bash
git clone https://github.com/deepakvijay2420/KernelGuard.git
cd KernelGuard/kernelguard

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install PyYAML

python3 kgctl.py plan -p policy/policy.example.yaml
python3 -m unittest discover -s tests -v
make
```

The BPF build requires a compatible Linux kernel and system dependencies including clang/LLVM with the BPF target, GCC, libbpf development headers and bpftool. Check the target machine with:

```bash
sudo python3 kgctl.py doctor
```

Do not load or detach BPF programs on a shared or production host. Perform live enforcement tests only in a disposable Ubuntu VM after checking kernel support and reviewing the policy.

## Current validation evidence

The reports in `evidence/stage-validation/` were supplied from an Ubuntu VM. They record 30 controller unit tests passing and selected tests for executable denial, synthetic sensitive-file taint/denial and taint-triggered IPv4 egress denial.

These are specific test results, not proof of universal attack coverage. Re-run the tests, BPF build, verifier/load/attach checks and live enforcement tests on a clean checkout before treating a new environment as validated.

## Limitations

- Prompt injection is not detected by analysing prompt text.
- Only selected operations covered by the implemented hooks are checked.
- IPv4 egress restrictions do not provide equivalent IPv6 filtering.
- Encrypted HTTPS content and URL paths are not inspected.
- Allowing an interpreter does not sandbox the scripts it executes.
- The project is a research prototype, not a production-ready security product.

## Future scope

Behavioural analysis, ML-based detection, dataset preparation, model evaluation and any model-driven risk response may be explored in future work. None of these capabilities is implemented in the current KernelGuard system.

## Documentation

- [KernelGuard implementation guide](kernelguard/README.md)
- [KernelGuard architecture](kernelguard/ARCHITECTURE.md)
- [Live demonstration guide](docs/LIVE_DEMO_GUIDE.md)
- [Validation evidence](evidence/stage-validation/README.md)
- [Security policy](SECURITY.md)
