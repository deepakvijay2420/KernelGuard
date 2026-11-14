# KernelGuard

**Unified Linux runtime security research prototype for Agentic AI workloads.**

KernelGuard combines administrator-defined Zero Trust policy, Linux cgroup isolation, eBPF/BPF-LSM enforcement, event monitoring, and behavioural-analysis research. It aims to restrict selected operating-system actions even when an AI agent is influenced by malicious prompts or untrusted tool output.

## One unified architecture

The canonical implementation is organised under [`kernelguard/`](kernelguard/README.md). It brings the BPF-LSM enforcement core together with the Gemini/LangChain agent example, policy, tests, event reader, and behavioural-analysis modules.

```text
AI Agent (LangChain + Gemini)
          | tool calls / subprocesses
          v
Linux workload inside cgroup v2
          v
KernelGuard BPF-LSM hooks <--- Administrator YAML policy / BPF maps
          |
      allow / audit / deny
          v
BPF ring buffer -> JSON event reader
          v
Behavioural analysis / ML / risk reporting
          v
Operator response (observe / restrict / freeze / kill)
```

**Enforcement principle:** deterministic kernel policy is the final authority. ML is an analysis signal; it must not silently rewrite kernel policy or claim to block an operation unless a tested enforcement path performs that action.

## Canonical source tree

| Path | Responsibility |
|---|---|
| `kernelguard/agent/` | LangChain/Gemini agent and tool calls |
| `kernelguard/kgctl.py` | Policy validation, BPF loading, map updates, cgroup lifecycle and response tiers |
| `kernelguard/bpf/` | BPF-LSM hooks and shared kernel/user-space structures |
| `kernelguard/tools/` | Ring-buffer event reader and policy lint |
| `kernelguard/policy/` | Administrator-authored YAML policies |
| `kernelguard/tests/` | Controller tests, policy tests, dry-run and controlled probes |
| `kernelguard/detection/` | Behavioural feature extraction, ML inference wrapper and risk fusion |
| `kernelguard/dataset/` | Dataset methodology and scenario collectors |
| `kernelguard/Makefile` | Build and test entry points |

See the [complete code architecture](kernelguard/ARCHITECTURE.md) for file-by-file explanations, API-key flow, kernel hooks, maps, runtime sequence and limitations.

## Safe quick start

From the repository root:

```bash
cd kernelguard
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
```

Build prerequisites include clang/LLVM with BPF target support, gcc, libbpf development headers, bpftool, a compatible Linux kernel with BPF-LSM and BTF support, and cgroup v2.

```bash
make
python3 kgctl.py doctor
```

**Do not load or detach BPF programs on a shared host until you inspect existing programs, links and pins and confirm ownership.** Use a disposable VM for live tests. Start in audit mode and only test enforce mode with a controlled policy.

## Current enforcement coverage

The BPF-LSM implementation currently contains hooks for:
- `bprm_check_security`: executable allow-list by device/inode and agent ID.
- `file_open`: configured sensitive filename-component taint/deny checks.
- `socket_connect` and `socket_sendmsg`: IPv4 destination/port egress checks.
- `bpf`: restrict agent use of the BPF syscall.
- `ptrace_access_check`: restrict agent ptrace access.

The controller associates a workload with a cgroup v2 ID, applies process and memory cgroup limits where supported, drops the child to an unprivileged account, and supplies only selected environment variables. The example policy is audit mode; it records violations but does not block them until enforce mode is deliberately selected.

## Gemini API key

The agent example uses `ChatGoogleGenerativeAI`. The Google integration normally reads `GOOGLE_API_KEY` from the process environment. The controller can pass this variable only when it is listed under `env_passthrough`. Never commit or print the key. Passing it to an agent makes it available to that process; this is not a secret vault.

## Behavioural ML and dataset scope

The detection modules define 23 run-level behavioural features, an ML inference wrapper and a risk-fusion helper. Dataset collectors create controlled command-sequence scenarios and parse the legacy monitor log format. These are currently a separate analysis/evaluation workstream: **they are not yet a verified live telemetry-to-ML-to-kernel enforcement pipeline**. Prompt-injection scenario labels do not prove a live model received a malicious prompt and autonomously selected the commands.

## Validation and limitations

The development VM previously passed Python/shell syntax checks, policy validation and 30 controller unit tests. Those checks do not establish BPF verifier acceptance, successful attachment or live enforcement. Runtime results must be recorded separately.

Known limitations include filename-component rather than full-path/file-operation policy, IPv4-only egress allow-listing, no HTTPS payload inspection, no prompt-text inspection in the kernel, no cryptographic proof of model provenance, and the fact that allowing an interpreter does not sandbox scripts executed inside it. ML model artifacts are not currently included in the canonical source copy.

## Repository history

Previous root-level experiments and `zta_v2/` are retained as historical source snapshots while the unified layout is validated. They are not separate active product versions. New canonical development should happen under `kernelguard/`; migrate or retire historical code only after comparing dependencies and test coverage.

- [Pre-unification README](docs/history/README-pre-unification.md)
- [Previous ZTA v2 README](docs/history/ZTA-v2-README.md)
- [Previous ZTA v2 architecture guide](docs/history/ZTA-v2-ARCHITECTURE.md)
- [Unified migration plan](docs/UNIFIED_MIGRATION.md)

**Research prototype notice:** KernelGuard is experimental, not a production security boundary.