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

The original controller tree previously passed Python/shell syntax checks, policy validation and 30 controller unit tests before this directory consolidation. The canonical copy has not yet been rerun on the target VM. Neither those earlier checks nor a future dry run establishes BPF verifier acceptance, successful attachment or live enforcement.

Known limitations include filename-component rather than full-path/file-operation policy, IPv4-only egress allow-listing, no HTTPS payload inspection, no prompt-text inspection in the kernel, no cryptographic proof of model provenance, and the fact that allowing an interpreter does not sandbox scripts executed inside it. ML model artifacts are not currently included in the canonical source copy.

## Repository history

Previous root-level experiments and `zta_v2/` are retained as historical source snapshots while the unified layout is validated. They are not separate active product versions. New canonical development should happen under `kernelguard/`; migrate or retire historical code only after comparing dependencies and test coverage.

- [Pre-unification README](docs/history/README-pre-unification.md)
- [Previous ZTA v2 README](docs/history/ZTA-v2-README.md)
- [Previous ZTA v2 architecture guide](docs/history/ZTA-v2-ARCHITECTURE.md)
- [Unified migration plan](docs/UNIFIED_MIGRATION.md)
- [Historical component map](docs/HISTORICAL_COMPONENTS.md)

**Research prototype notice:** KernelGuard is experimental, not a production security boundary.

---

# Research scope and implementation details

## What problem does KernelGuard address?

Agentic AI applications can select tools and cause operating-system actions. A malicious instruction embedded in a document or other untrusted content may influence an agent to request an action that the system owner did not intend. If the agent can invoke Linux commands, read files or access a network, the risk moves beyond the model response and into the host operating system.

KernelGuard investigates how to place a deterministic Linux security boundary around an AI-agent workload. The main research scenario is **prompt injection that attempts to trigger an unauthorized command**, with restricted executable execution (especially shell and sudo) used as the observable operating-system action.

KernelGuard does not inspect or understand the prompt inside the kernel. It controls the resulting operating-system operation. This distinction is central to the threat model.

## Primary attack scenario: prompt injection to restricted execution

The intended experiment is:

1. Start a controlled LangChain/Gemini agent with a narrow set of tools.
2. Provide a benign task and a controlled document containing an adversarial instruction.
3. Observe whether the agent attempts an additional tool or process action outside the intended task.
4. The controller places the agent process tree in a dedicated cgroup v2.
5. The BPF-LSM hook identifies the operation as belonging to that registered cgroup.
6. The administrator's ZTA policy checks whether the executable is permitted.
7. In audit mode, KernelGuard records the policy violation while allowing the operation to continue. In enforce mode, it returns `-EPERM` for a denied operation.
8. The event reader exports the decision for later analysis.

The two dataset scenario labels most closely related to this demonstration are `prompt_injection_sudo` and `prompt_injection_bash`. **The existing dataset generator runs scripted command sequences directly. Those labels do not prove that a live LLM received a malicious document or independently selected the commands.** A separate agent-driven experiment with captured prompts, tool-call traces and kernel events is required to make that stronger claim.

## Other controlled attack-like scenarios

The current attack dataset generator defines ten command-sequence scenarios:

| Scenario | What it represents |
|---|---|
| `prompt_injection_sudo` | Normal-looking activity followed by a non-interactive sudo attempt |
| `prompt_injection_bash` | File inspection followed by a bash command |
| `shell_execution_chain` | Nested shell invocation |
| `password_utility` | Invocation of the password utility with a help argument |
| `tmp_executable` | Execution of a harmless copied executable from `/tmp` |
| `unknown_executable` | Execution of a harmless test binary not in the expected allow-list |
| `benign_to_sudo` | Benign commands followed by a sudo attempt |
| `benign_to_shell` | Benign commands followed by a shell attempt |
| `repeated_sudo` | Repeated non-interactive sudo attempts |
| `repeated_shell` | Repeated shell attempts |

The generator uses harmless test operations and copies of benign binaries such as `/bin/echo` and `/bin/true`. These are controlled attack-like simulations, not malware samples or real intrusions.

## How the Zero Trust policy works

The active policy format is the version-1 YAML schema under `kernelguard/policy/`. The administrator owns the policy. The AI agent does not get permission to edit or reload it.

The policy is applied through the controller:

```text
Administrator writes policy YAML
              |
              v
kgctl.py plan -p policy.yaml
              |
       Validate structure
       Resolve executable paths
       Resolve network hosts
              |
              v
kgctl.py load
       Load and attach BPF-LSM
              |
              v
kgctl.py apply -p policy.yaml
       Populate pinned BPF maps
       Record policy SHA-256
              |
              v
kgctl.py run research_agent -- COMMAND
       Create cgroup v2
       Register cgroup ID
       Drop privileges
       Launch the agent
              |
              v
       BPF-LSM checks each covered operation
```

The policy expresses these controls:

- **Agent identity:** a controller-created cgroup v2 ID identifies the managed workload and its descendants.
- **Executable authorization:** only executable device/inode identities registered in the agent's `exec.allow` list are permitted. Unlisted executables are violations.
- **Sensitive files:** entries under `sensitive.taint` are allowed to be opened but mark the agent as tainted; entries under `sensitive.deny` are denied according to the configured mode.
- **Network egress:** destination IPv4 address and port entries form the allow-list. The policy can default egress to deny. A tainted agent is restricted to the configured allow-list.
- **Self-protection:** agent attempts to use the BPF syscall or ptrace are treated as policy violations.
- **Resource isolation:** the controller can set cgroup PID and memory limits, use an unprivileged account, clear supplementary groups, set `no_new_privs`, and pass only explicitly listed environment variables.
- **Policy integrity:** the controller stores a SHA-256 hash when applying a policy and refuses to run an agent if the policy file has changed since it was applied.

### Audit versus enforce

| Mode | Kernel hook behaviour | Intended use |
|---|---|---|
| `audit` | Emit an audit violation and return success | Learn legitimate workload requirements and tune policy |
| `enforce` | Emit a deny event and return `-EPERM` | Block a prohibited operation |

The example policy starts in audit mode. Do not claim that a rule blocks an action until the same scenario has been tested in enforce mode and the operation's failure has been observed.

### Important policy limitations

The current implementation uses filename-component matching for sensitive-file rules, not a complete file-operation policy. Network allow-listing is IPv4 address/port based. It does not inspect HTTPS payloads, URL paths or prompt contents. Allowing an interpreter does not sandbox scripts passed to that interpreter. The cgroup identifies the managed workload; it is not cryptographic proof of the model or prompt provenance.

## Dataset and machine-learning research

The dataset methodology is documented in [KernelGuard dataset documentation](kernelguard/dataset/README.md). It describes controlled benign and attack-like command workloads collected from the earlier text-log monitoring pipeline.

The documented experiment plan contains:

| Class | Planned runs | Recorded events in the documented dataset |
|---|---:|---:|
| Benign | 800 | 1,971 |
| Attack-like | 300 | 810 |
| **Total** | **1,100** | **2,781** |

The benign set comprises 40 simple task types repeated 10 times and 20 composite workflow types repeated 20 times. The attack-like set comprises ten scenario types repeated 30 times. Actual CSV row counts should be used when reporting a regenerated dataset.

The feature extractor defines 23 run-level behavioural features, including event count, process/path diversity, process changes, sequence entropy, UID/PID diversity, path-depth ratios, event rate, inter-event timing and burst count. The ML wrapper loads a separately supplied joblib model and feature list. The model artifacts are not included in the canonical source copy.

**Data provenance limitation:** the existing dataset generators read `logs/kernelguard_live.log` using the earlier `PID | UID | PROCESS | PATH | RISK | REASON | ACTION` format. They are not yet consuming the current BPF ring-buffer JSON events. Do not describe the dataset as collected from the canonical BPF-LSM pipeline until an adapter and an end-to-end capture run have been completed.

ML is an out-of-band behavioural signal. It does not synchronously block a syscall and must not be presented as the kernel enforcement authority.

## Code architecture: where each responsibility lives

| Path | What it contains |
|---|---|
| `kernelguard/agent/` | Controlled LangChain/Gemini agent and its registered tools |
| `kernelguard/kgctl.py` | Policy validation, BPF lifecycle, map population, cgroup creation, privilege drop and response commands |
| `kernelguard/bpf/kg_zta.bpf.c` | BPF-LSM enforcement hooks and map lookups |
| `kernelguard/bpf/kg_common.h` | Structures shared by BPF and user space |
| `kernelguard/tools/kg_events.c` | Ring-buffer reader that prints JSON Lines |
| `kernelguard/policy/` | Administrator-owned policy examples |
| `kernelguard/detection/` | 23-feature extraction, ML inference wrapper and risk fusion |
| `kernelguard/dataset/` | Dataset methodology and controlled scenario generators |
| `kernelguard/tests/` | Controller tests, dry-run checks and controlled probes |
| `kernelguard/systemd/` | Service configuration for the canonical runtime |
| `kernelguard/Makefile` | BPF object and event-reader build/test targets |
| `model/` | Earlier model training and evaluation experiments/artifacts |
| `dataset/` | Earlier dataset material and generated records |
| `results/` | Research evaluation outputs |

### Runtime architecture

```text
                    ADMINISTRATOR
                         |
                  YAML ZTA policy
                         |
                         v
                 KernelGuard Controller
                    kgctl.py
                         |
          +--------------+--------------+
          |                             |
          v                             v
   cgroup v2 isolation             BPF maps
          |                             |
          v                             v
   LangChain / Gemini Agent ---> Linux system operation
                                        |
                                        v
                                  BPF-LSM hooks
                                        |
                              +---------+---------+
                              |                   |
                              v                   v
                         Allow / Deny        Ring buffer
                                                  |
                                                  v
                                            kg_events
                                                  |
                                                  v
                                      Behavioural analysis
                                      (separate pipeline)
                                                  |
                                                  v
                                          Operator review
```

The kernel hook is the synchronous enforcement point. The event reader exports evidence. Dataset and ML modules support offline research and are not yet a verified live event-to-model-to-response pipeline.

## Repository cleanup policy

The canonical active implementation is `kernelguard/`. Historical directories must be reviewed against the canonical source and test coverage before removal. The legacy `zta_v2/` directory is a historical snapshot candidate for renaming to `archive/zta_legacy/`; the old `agents/`, `daemon/`, `ebpf/`, `policies/` and root-level scripts must be individually checked for unique experiments, dependencies and results before they are archived or deleted. Dataset CSVs, trained model artifacts, evaluation scripts and result files must be retained when they are required to reproduce the research.

See [the repository audit and cleanup plan](docs/REPOSITORY_AUDIT.md) before removing historical files.
