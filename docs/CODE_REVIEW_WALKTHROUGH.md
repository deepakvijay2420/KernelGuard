# KernelGuard Code Review Walkthrough

This document is a practical checklist for a reviewer who has cloned the repository for the first time. It follows the supplied AmritaCSN code-review format: quick setup, a short demonstration, then a module-by-module walkthrough.

The canonical implementation is under `kernelguard/`. Run the commands below from that directory unless stated otherwise.

## 1. What the project does

KernelGuard is a Linux runtime-security research prototype for constraining selected operating-system actions performed by managed Agentic AI workloads.

It uses:

- **BPF-LSM** to check selected executable, file-open, network, BPF and ptrace operations inside the Linux kernel.
- **cgroup v2** to identify the process tree belonging to a managed agent run.
- **Administrator-owned YAML policy** to define executable permissions, sensitive filename actions and network egress rules.
- **A userspace controller** to validate policy, load/apply BPF maps, start the workload with reduced privileges and manage response tiers.
- **A BPF ring buffer and event reader** to expose decisions as JSON Lines.
- **Separate research modules** for behavioural feature extraction, ML experiments and risk fusion. These modules are advisory/offline in the current architecture; they are not called synchronously from the BPF hook.

This is a research prototype, not a production security product.

## 2. Repository layout

```text
KernelGuard/
├── README.md                         # Project overview and full setup guide
├── kernelguard/                      # Canonical active implementation
│   ├── kgctl.py                      # Main controller / CLI
│   ├── Makefile                      # Builds BPF object and event reader
│   ├── agent/
│   │   └── langchain_gemini_agent.py # Optional agent integration example
│   ├── bpf/
│   │   ├── kg_zta.bpf.c              # BPF-LSM hooks and map lookups
│   │   ├── kg_common.h               # Shared kernel/userspace data structures
│   │   └── vmlinux.h                 # CO-RE kernel type definitions
│   ├── policy/
│   │   ├── policy.example.yaml       # Main policy example
│   │   ├── policy.hardened.yaml      # Stricter example policy
│   │   └── dangerous_commands.yaml   # Command-family reference
│   ├── tools/
│   │   ├── kg_events.c               # Ring-buffer reader; JSONL output
│   │   └── policy_lint.py            # Policy linting helper
│   ├── tests/
│   │   ├── test_kgctl.py             # Controller and C/Python ABI tests
│   │   ├── dry_run.sh                # Safe syntax/policy/test workflow
│   │   └── attack_probe.py           # Controlled probe utility
│   ├── detection/
│   │   ├── behavior_features.py      # 23-feature extraction
│   │   ├── behavior_ml.py            # Loads external ML model artifacts
│   │   └── risk_fusion.py             # Advisory ZTA/ML result combination
│   ├── dataset/                      # Dataset method and generators
│   └── systemd/                      # Optional service unit
├── research/
│   ├── dataset/                      # Controlled research datasets
│   ├── models/                       # ML training/evaluation scripts
│   └── results/                      # Saved research results
├── docs/
│   ├── architecture.md               # Component diagram and data flow
│   ├── ZTA_POLICY_GUIDE.md           # Detailed policy explanation
│   └── CODE_REVIEW_WALKTHROUGH.md    # This document
└── archive/                          # Historical implementations, not active
```

The `archive/` directory contains earlier experiments retained for provenance. Do not use it for the current demo. The active build and run instructions use only `kernelguard/`.

## 3. Requirements

### 3.1 Safe policy/test review

For policy validation and unit tests:

- Ubuntu/Linux
- Python 3.10 or newer
- PyYAML
- GCC (the ABI layout test uses GCC when available)
- GNU Make

Install the Python dependency:

```bash
python3 -m pip install --user PyYAML
```

### 3.2 BPF build and live runtime

For BPF compilation and live kernel operation, also install:

```bash
sudo apt update
sudo apt install -y clang llvm gcc make pkg-config libbpf-dev bpftool \
  linux-headers-$(uname -r) python3 python3-venv python3-pip
```

The live runtime additionally needs:

- Linux kernel 5.15 or newer (the target kernel must support the required BPF-LSM features);
- `CONFIG_BPF_LSM=y`;
- `bpf` present in the active LSM list;
- kernel BTF at `/sys/kernel/btf/vmlinux`;
- cgroup v2 and bpffs mounted;
- root for BPF load/apply and cgroup management;
- an existing unprivileged account matching the policy's `run_as` field (the example uses `kgagent`).

Do not assume every Linux distribution or VM image has these enabled. Run `doctor` before attempting live loading.

## 4. Clone and first run

### 4.1 Clone

From a clean terminal:

```bash
git clone https://github.com/deepakvijay2420/KernelGuard.git
cd KernelGuard/kernelguard
```

### 4.2 Fast, safe smoke test (no root, no BPF attachment)

This is the recommended first command sequence for a reviewer. It validates the policy and runs the controller tests without loading or detaching kernel programs:

```bash
python3 -m pip install --user PyYAML
python3 kgctl.py plan -p policy/policy.example.yaml
make test
```

For the full safe dry-run, run:

```bash
bash tests/dry_run.sh
```

What the commands prove:

| Command | Expected result | What it proves |
|---|---|---|
| `kgctl.py plan` | Prints agent IDs, modes, map-entry counts and `policy OK` | YAML is valid and can be translated into a map plan. No BPF map is changed. |
| `make test` | Python unit tests pass | Controller validation and C/Python structure packing tests pass. |
| `tests/dry_run.sh` | Ends with `DRY RUN COMPLETE` | Syntax, policy and unit checks completed without root, cgroup creation or BPF attachment. |

These checks do **not** prove BPF verifier acceptance, attachment or live kernel enforcement.

## 5. Build and runtime demonstration

The full runtime demo takes longer than the safe smoke test and must be prepared on a disposable Ubuntu VM. For the review, build and validate it before the presentation.

From `KernelGuard/kernelguard/`:

```bash
make
sudo python3 kgctl.py doctor
```

Review the policy first:

```bash
python3 kgctl.py plan -p policy/policy.example.yaml
```

The sample policy uses **audit** mode. On a disposable VM only, after confirming the kernel prerequisites and inspecting existing BPF programs/links/pins:

```bash
sudo python3 kgctl.py load
sudo python3 kgctl.py apply -p policy/policy.example.yaml
sudo python3 kgctl.py status
```

Open a second terminal to stream events:

```bash
cd KernelGuard/kernelguard
sudo python3 kgctl.py events
```

Run a small managed command in the first terminal:

```bash
sudo python3 kgctl.py run research_agent -- /usr/bin/python3 --version
```

Expected behaviour:

- The controller prints the agent name, numeric agent ID, mode and cgroup ID.
- The command runs as the unprivileged user configured in the YAML.
- The BPF hooks identify the process through its registered cgroup.
- The event reader prints JSON Lines for covered operations.
- After the process exits, the controller removes the agent's cgroup registration and runtime state.

The sample policy is in audit mode. A policy violation is recorded as `audit_deny` but allowed to continue. To demonstrate a block, use a reviewed enforce-mode test policy in a disposable VM and confirm both the `deny` event and the application's `EPERM` result. Do not claim blocking from an audit-only run.

Unload only the instance you loaded, after checking ownership and stopping managed workloads:

```bash
sudo python3 kgctl.py unload
```

## 6. Module-by-module walkthrough: inputs and outputs

| Module | Main file | Input | Output / responsibility |
|---|---|---|---|
| Policy configuration | `policy/policy.example.yaml` | Administrator's YAML rules | Agent IDs, mode, run-as user, executable list, sensitive names, egress rules and resource limits |
| Controller | `kgctl.py` | CLI arguments and YAML policy | Validates policy, builds map entries, manages BPF lifecycle, creates cgroups, drops privileges and handles response tiers |
| Shared ABI | `bpf/kg_common.h` | C structure and enum definitions | Agreed map-key/value and event-record layouts |
| Kernel enforcement | `bpf/kg_zta.bpf.c` | Linux LSM hook arguments, current cgroup ID and BPF maps | Allow, audit-and-allow or enforce-deny decision; event record |
| Event reader | `tools/kg_events.c` | Pinned BPF ring-buffer map | JSON Lines on stdout |
| Agent example | `agent/langchain_gemini_agent.py` | User task and Gemini API response | Registered tool requests and final agent response |
| Unit tests | `tests/test_kgctl.py` | Test policies, temporary files and C header | Pass/fail results for validation and C/Python data layout |
| Dry-run | `tests/dry_run.sh` | Current source tree | Syntax, policy and unit-test results without BPF attachment |
| Behaviour features | `detection/behavior_features.py` | Compatible event table/DataFrame | 23 run-level behavioural features |
| ML inference wrapper | `detection/behavior_ml.py` | Feature vector plus separately supplied joblib artifacts | Prediction, probability and LOW/MEDIUM/HIGH risk |
| Risk fusion | `detection/risk_fusion.py` | ZTA decision and ML risk | Advisory ALLOW, DENY or REVIEW result |

## 7. Suggested 5-minute demonstration

Use this order to keep the demo focused:

1. Show the repository root and point out that `kernelguard/` is the active implementation.
2. Run `python3 kgctl.py plan -p policy/policy.example.yaml`.
3. Run `make test` (or show the already completed output if build/test time is longer).
4. If the BPF runtime is already loaded in the disposable VM, show `kgctl.py status`.
5. Show one event from `kgctl.py events` and explain the hook, cgroup ID, agent ID and verdict.
6. Show a previously captured enforce-mode denial and its `EPERM` result. Keep the raw log and test command ready.

Do not use an external Gemini API call as the only demo path. Network availability, API quota and model response time are external dependencies. Use the deterministic local command test as the reliable baseline.

## 8. Suggested 15-minute code walkthrough

| Time | File / topic | What to explain |
|---:|---|---|
| 1 min | README and architecture | Problem, threat model and high-level data flow |
| 2 min | `policy/policy.example.yaml` | Administrator-owned policy, agent identity, mode and permissions |
| 3 min | `kgctl.py` | Policy validation, inode resolution, SHA-256 drift check, BPF map update, cgroup creation and privilege drop |
| 3 min | `bpf/kg_common.h` and `bpf/kg_zta.bpf.c` | Map structures, cgroup lookup, exec/file/network hooks and audit/enforce return values |
| 2 min | `tools/kg_events.c` | Ring-buffer polling and JSON event formatting |
| 2 min | `tests/` | What unit/dry-run checks prove and what they do not prove |
| 2 min | `detection/` and `research/` | Explain the separate offline ML workflow and its integration boundary |

For the detailed ZTA explanation, use [ZTA Policy Guide](ZTA_POLICY_GUIDE.md). For the component diagram and file responsibilities, use [Architecture](architecture.md).

## 9. ZTA policy explanation: the short version

The explanation to give the reviewer:

> The administrator writes the YAML policy. The controller validates it and translates it into BPF map entries. When the controller starts an agent, it places the process in a dedicated cgroup v2 and registers that cgroup ID with an agent ID and policy mode. The agent runs as a non-root user with a minimal environment and no-new-privileges. When the agent executes a program, opens a configured sensitive file or connects to a network destination, the BPF-LSM hook obtains the current cgroup ID, finds the agent configuration and checks the relevant map. If the operation is allowed, it continues. If it violates policy, audit mode records a would-deny event but allows it; enforce mode records a deny and returns `-EPERM`. Sensitive-file taint marks the whole agent cgroup and causes subsequent egress to be checked against the IPv4 allow-list.

Key terms:

- **Agent ID:** numeric policy identity assigned in YAML.
- **cgroup ID:** runtime identity for the managed process tree.
- **BPF map:** kernel-resident lookup table containing policy data.
- **Ring buffer:** telemetry channel from kernel to user space; not the policy engine.
- **Audit:** observe a would-be violation without blocking.
- **Enforce:** block the covered operation with `-EPERM`.
- **Taint:** mark a workload after it opens a configured sensitive file; this can activate egress restrictions.

## 10. Current implementation boundaries to state honestly

- The BPF hooks do not read prompts or determine whether text is malicious.
- The current network allow-list is IPv4-only. When a workload is egress-restricted, IPv6 is treated as unlisted; no IPv6 allow-list exists.
- Sensitive filename rules are global and match the final filename component; they are not per-agent full-path rules.
- The hooks cover selected operations, not every Linux syscall or every possible file/network path.
- An allowed interpreter can still execute scripts; executable allow-listing is not a complete language sandbox.
- Behavioural ML training/evaluation and inference/risk-fusion code exist in the repository, but the live BPF JSON-to-feature-to-model-to-controller response path is not fully integrated/verified.
- The ML model in the documented repository is not an LSTM Autoencoder. LLM semantic adjudication is not implemented in the canonical runtime path.
- Historical attack-like dataset labels describe controlled command sequences; do not claim they all represent autonomous live LLM prompt-injection decisions.
- A successful unit test or BPF compile does not prove runtime enforcement. For an enforcement claim, show the actual enforce-mode test and observed `EPERM`.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| `ModuleNotFoundError: yaml` | Install PyYAML in the Python environment used for the command. |
| `policy OK` but no BPF programs loaded | Expected after `plan`; it only validates and previews policy. |
| `BPF object missing` | Run `make` from `kernelguard/` and check the Makefile build output. |
| `bpf` absent from active LSM list | Check kernel config and boot parameters; reboot may be required. |
| Kernel BTF missing | Check `/sys/kernel/btf/vmlinux` and the target kernel package. |
| cgroup v2 unavailable | Check `/sys/fs/cgroup/cgroup.controllers` and mount configuration. |
| Agent cannot execute a command | Check the executable allow-list and the audit/enforce event. Resolve the actual binary path and inode. |
| Network request fails | Check egress mode, taint state, IPv4 allow-list, DNS resolution and external API availability. |
| No event output | Confirm the BPF program is loaded, the event reader is built, and the events map is pinned. |

## 12. Safety and review checklist

Before the live review:

- [ ] Clone the repository into a clean directory.
- [ ] Install the documented dependencies.
- [ ] Run `kgctl.py plan`.
- [ ] Run `make test` and `tests/dry_run.sh`.
- [ ] Build the BPF object and reader on the target VM.
- [ ] Run `kgctl.py doctor`.
- [ ] Use a disposable VM for live BPF operations.
- [ ] Inspect existing BPF links/pins before load or unload.
- [ ] Keep the policy in audit mode until legitimate operations are reviewed.
- [ ] Prepare an enforce-mode test and preserve the raw `EPERM` evidence.
- [ ] Never commit API keys, tokens, private keys, or local secrets.
- [ ] Be ready to explain each source file in the walkthrough order above.
