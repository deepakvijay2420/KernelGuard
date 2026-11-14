# KernelGuard ZTA v2

**Kernel-level runtime security for Linux Agentic AI processes using eBPF/BPF-LSM and Zero Trust policy.**

This directory contains the current ZTA v2 implementation. The original v1 implementation remains in the repository for comparison and project history; this document describes only the code under `zta_v2/`.

> **Research prototype:** ZTA v2 is under active validation. Unit tests and dry-run checks do not prove that the BPF object passes the target kernel verifier or that live enforcement works. Do not use it as a production security boundary.

## 1. What ZTA v2 is intended to do

An Agentic AI application can invoke tools that execute programs, open files, or communicate over a network. A malicious prompt or untrusted tool output may influence an agent to request an unintended operating-system action.

ZTA v2 places policy checks at selected Linux Security Module (BPF-LSM) hooks. The controller starts an agent inside a dedicated cgroup v2; kernel code uses that cgroup identity to decide whether the process belongs to a registered agent. The policy is supplied by an administrator in YAML and compiled into BPF maps.

**Design principle:** the AI model does not write or dynamically change the kernel policy. The administrator defines the policy; the controller validates and loads it; BPF-LSM performs the final kernel-side allow/deny decision.

## 2. Architecture

```text
 Administrator
      |
      v
 policy/policy.example.yaml
      |
      v
 kgctl.py  ---- validate / resolve / compile policy
      |                         |
      |                         v
      |                    Pinned BPF maps
      |                         |
      v                         v
 kgctl.py run AGENT -- CMD   BPF-LSM programs
      |                         ^
      v                         |
 Dedicated cgroup v2       Linux security hooks
      |                         ^
      v                         |
 Agent process + children ------+
                                |
                         decision events
                                |
                         BPF ring buffer
                                |
                         tools/kg_events
                                |
                         JSON event stream
```

### Main components

| Component | Responsibility |
|---|---|
| `bpf/kg_zta.bpf.c` | BPF-LSM programs and kernel-side policy checks |
| `bpf/kg_common.h` | Shared C structures and hook/verdict definitions |
| `kgctl.py` | Policy validation, BPF loading, map population, cgroup creation and agent lifecycle |
| `policy/policy.example.yaml` | Example administrator-authored policy |
| `tools/kg_events.c` | Reads ring-buffer events and prints JSON lines |
| `tests/test_kgctl.py` | Unit tests for policy/controller logic and C/Python data-layout consistency |
| `tests/dry_run.sh` | Safe static validation and unit-test runner; does not load BPF |
| `tests/attack_probe.py`, `tests/policy.test.yaml` | Probe scenarios and a dedicated test policy for later controlled runtime testing |
| `Makefile` | Build and test targets |

## 3. Kernel hooks currently implemented

The BPF source contains six BPF-LSM hook programs:

| Hook | Purpose in this prototype |
|---|---|
| `bprm_check_security` | Checks whether an agent is allowed to execute a binary |
| `file_open` | Checks configured sensitive filename components and can deny or taint |
| `socket_connect` | Checks IPv4 connection destinations against the egress policy |
| `socket_sendmsg` | Checks UDP send destinations, including unconnected sends |
| `bpf` | Restricts agent use of the `bpf()` system call |
| `ptrace_access_check` | Restricts ptrace access involving an agent |

The hooks observe specific kernel operations. They do not understand the semantic meaning of an AI prompt and cannot independently prove that an action originated from an AI model.

## 4. Agent identity and provenance

ZTA v2 associates an agent with a **cgroup v2 ID**, registered by the controller. Processes launched through `kgctl.py run` are placed in the agent's dedicated cgroup; child processes inherit that cgroup membership.

This is stronger than relying only on a PID or process name because PIDs can be reused and processes can be re-parented.

**Important boundary:** cgroup membership identifies a process as belonging to a controller-launched agent workload. It does not cryptographically prove that an AI model generated a particular command. A human who runs a command outside the registered agent cgroup is not automatically classified as an agent.

## 5. Policy file explained

The example policy is `policy/policy.example.yaml`. It is deliberately small so that each rule can be reviewed. It is an administrator-defined security policy, not a prompt or instruction sent to the model.

### Policy sections

| YAML key | Meaning |
|---|---|
| `version` | Policy schema version; currently `1` |
| `sensitive.taint` | Sensitive filename components whose open marks the agent as tainted |
| `sensitive.deny` | Sensitive filename components whose open is denied in enforce mode |
| `agents.<name>.id` | Unique numeric agent ID (1–63) |
| `mode` | Required per-agent mode: `audit` or `enforce` |
| `run_as` | Unprivileged Linux account used to launch the agent |
| `workdir` | Working directory for the agent |
| `env_passthrough` | Explicit environment variables passed to the agent |
| `limits.pids_max` | cgroup process-count limit |
| `limits.memory_max` | cgroup memory limit in bytes |
| `exec.allow` | Executables the agent is allowed to launch |
| `network.egress_default` | Default handling for unlisted egress destinations |
| `network.allow` | Explicit IPv4 address/port or hostname/port entries |

Executable entries are resolved by the controller and represented in the BPF policy using device and inode identity. The optional `sha256` field can be used to pin the expected executable content when configured.

### Example policy flow

1. The administrator writes the YAML policy.
2. `kgctl.py plan` validates the policy and displays the proposed configuration without loading BPF.
3. `kgctl.py apply` compiles the rules into the pinned BPF maps.
4. `kgctl.py run` launches the configured workload in its dedicated cgroup.
5. BPF-LSM checks the registered agent's relevant kernel operations.
6. Events can be observed through `kgctl.py events`.

### Audit versus enforce

- **audit:** a policy violation is recorded as an `audit_deny` event but the operation is not blocked by that policy check.
- **enforce:** a denied operation is rejected by the kernel hook.

Start in audit mode, inspect events, adjust legitimate allow-list entries, and only then test enforce mode in a disposable VM.

## 6. Requirements

The controller documents these prerequisites:

- Linux kernel 5.15 or newer
- `CONFIG_BPF_LSM=y`
- `bpf` enabled in the active LSM list (for example, visible in `/sys/kernel/security/lsm`)
- cgroup v2
- bpffs mounted at `/sys/fs/bpf`
- `bpftool`
- Clang with BPF target support
- GCC, libbpf development headers/library
- Python 3 and PyYAML

The exact availability of BPF features depends on the running kernel and distribution configuration. A successful prerequisite check is not the same as a successful BPF load.

## 7. Build and safe validation

From the repository root:

```bash
cd zta_v2
sudo apt update
sudo apt install -y clang gcc make libbpf-dev bpftool python3-yaml
make
make test
bash tests/dry_run.sh
```

The dry-run script performs Python and shell syntax checks, validates the example and test YAML policies, and runs the unit tests. It does **not** load or unload BPF programs, alter BPF maps, create cgroups, or launch agents.

A previous validation run on the maintainer's Ubuntu VM reported all 30 unit tests passing and the dry run completing. This is evidence for those checks only; rerun them on the machine used for the review.

## 8. Controlled runtime validation

Live enforcement must be validated separately on a disposable Linux VM that meets the BPF-LSM requirements.

Before attempting runtime validation:

1. Take a VM snapshot.
2. Inspect existing BPF programs, links and bpffs pins.
3. Confirm that any KernelGuard BPF object and pin directory belong to this test instance.
4. Do not detach or unload unrelated BPF programs.
5. Begin with an audit policy and a harmless test agent.
6. Save the kernel event stream and command output as evidence.
7. Test each hook independently before running a combined adversarial scenario.

Useful read-only preflight commands:

```bash
uname -r
grep -E 'CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_BPF_LSM=|CONFIG_DEBUG_INFO_BTF=' /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
mount | grep -E 'bpf|cgroup'
sudo bpftool feature probe kernel
sudo bpftool prog show
sudo bpftool link show
```

Then inspect the proposed policy without loading it:

```bash
sudo ./kgctl.py doctor
./kgctl.py plan -p policy/policy.example.yaml
```

Only proceed to `load`, `apply`, and `run` after the preflight and ownership checks are understood. Keep the test workload isolated from your normal desktop session.

> **Test-suite safety note:** review `tests/bypass_suite.sh` before running it. The current script contains `kgctl.py unload --force` cleanup/setup calls. Do not run it on a machine with other active KernelGuard state or unrelated BPF activity until that behaviour has been made ownership-scoped and safe. The safe dry-run command above does not have this behaviour.

## 9. Current validation status

| Area | Status |
|---|---|
| Python controller syntax and policy validation | Covered by dry-run/unit tests |
| YAML example and test policy structure | Covered by dry-run |
| C/Python shared structure layout | Covered by unit test |
| Unit tests | 30 tests reported passing in the maintainer's recent run |
| BPF object compilation on the target VM | Must be recorded from the target environment |
| BPF verifier acceptance and live attachment | Not established by the dry-run result |
| Real kernel-side allow/deny behaviour for every hook | Requires controlled runtime evidence |
| Full bypass/attack suite | Not established as passing; inspect and make the script safe before execution |
| ML-based decision integration into ZTA v2 enforcement path | Not established in this v2 module |

Do not describe a feature as runtime-verified unless the corresponding test was run on the target kernel and its evidence was saved.

## 10. Known limitations

- File policy matches the final filename component, not a complete directory path or read/write intent.
- Network allow-listing is IPv4-focused; IPv6 coverage is not established.
- Allowing an interpreter such as Python permits many scripts to run inside that interpreter; executable allow-listing alone does not constrain the script's internal behaviour.
- A configured network destination can still be abused for unintended data transfer.
- The current cgroup limits shown in the example cover process count and memory; CPU and I/O controls are not described as implemented here.
- Optional executable hashes are not equivalent to mandatory immutable binary verification.
- Cgroup provenance associates a process with an agent workload; it does not prove model-level authorship of each action.
- The ZTA v2 directory does not establish a complete online ML/LLM enforcement integration.
- Human approval workflow, full filesystem sandboxing, and IPv6 policy require further work.

## 11. Suggested next development stages

1. Complete safe BPF object build and verifier/load validation on the target VM.
2. Make runtime test setup and cleanup ownership-scoped; remove unsafe global force-unload behaviour.
3. Produce per-hook positive and negative test evidence.
4. Expand policy schema only alongside validation tests and clear semantics.
5. Add stronger filesystem controls and document exact read/write behaviour.
6. Add IPv6 policy coverage.
7. Integrate behavioural analysis out of band, while keeping final enforcement deterministic.
8. Correlate agent framework tool-call metadata with cgroup and kernel events to improve AI-versus-human provenance.
9. Add reproducible evaluation datasets, metrics and experiment records before making ML effectiveness claims.

## 12. Command reference

```bash
./kgctl.py doctor
./kgctl.py plan -p policy/policy.example.yaml
sudo ./kgctl.py load
sudo ./kgctl.py apply -p policy/policy.example.yaml
sudo ./kgctl.py run research_agent -- /usr/bin/python3 /path/to/agent.py
sudo ./kgctl.py events
sudo ./kgctl.py status
sudo ./kgctl.py tier research_agent restrict
sudo ./kgctl.py tier research_agent freeze
sudo ./kgctl.py tier research_agent thaw
sudo ./kgctl.py tier research_agent kill
sudo ./kgctl.py unload
```

Use operational commands only in a dedicated test VM after checking the current state and the controller's help output. In particular, `unload` detaches KernelGuard's own pinned programs and should be used only when you have confirmed the target paths and active agents.

## 13. Relationship to v1

The root repository contains the original v1 work and the current ZTA v2 module. Keep the v1 code and its historical documentation for comparison. Use this document as the source of truth for the implementation under `zta_v2/`; do not assume every v1 README capability is implemented in v2.

## 14. License and research use

This is an academic research prototype. Review the repository's top-level license and third-party dependency licenses before redistribution or deployment. Validate all security claims against reproducible test evidence.
