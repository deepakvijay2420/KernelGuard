# KernelGuard

**A Linux runtime-security research prototype for constraining Agentic AI workloads.**

KernelGuard investigates how to place a deterministic operating-system security boundary around AI agents that can invoke tools, launch processes, read files, or communicate over a network. Its primary research scenario is an agent influenced by untrusted content (including indirect prompt injection) attempting an OS action outside the administrator's intended permissions.

> **Research prototype — not production-ready.** The repository contains a canonical BPF-LSM/ZTA implementation, historical experiments, a controlled behavioural dataset, ML evaluation outputs, and a small runtime experiment. The evidence does not yet establish a fully integrated live LLM → BPF telemetry → ML → automated enforcement pipeline.

## Contents

- [Problem and motivation](#1-problem-and-motivation)
- [What KernelGuard does](#2-what-kernelguard-does)
- [Architecture and execution flow](#3-architecture-and-execution-flow)
- [Repository structure](#4-repository-structure)
- [Zero Trust policy](#5-zero-trust-policy)
- [Kernel enforcement and supported controls](#6-kernel-enforcement-and-supported-controls)
- [Behavioural ML and dataset](#7-behavioural-ml-and-dataset)
- [Experimental results](#8-experimental-results)
- [Related work and research positioning](#9-related-work-and-research-positioning)
- [Research contributions and novelty](#10-research-contributions-and-novelty)
- [Attack coverage and limitations](#11-attack-coverage-and-limitations)
- [Installation and safe validation](#12-installation-and-safe-validation)
- [Current status and future work](#13-current-status-and-future-work)
- [References](#14-references)

## 1. Problem and motivation

Agentic AI applications differ from ordinary chat systems because an agent can select tools and cause real operating-system side effects. A model may request a Python tool, which launches a subprocess; that subprocess may execute a shell, access a file, or open a network connection. Untrusted documents, retrieved pages, tool output, or other context can influence the agent's decisions. This creates a path from a semantic manipulation (for example, indirect prompt injection) to an OS-level action.

Prompt instructions and application-level checks are useful, but they are not a complete OS security boundary. A process that has permission to execute a program or access a file can perform that action regardless of whether the model's final natural-language answer appears safe.

**Research question:** Can a Linux kernel-enforced, administrator-owned Zero Trust policy constrain the OS actions of an AI-agent workload independently of the agent's own prompt instructions?

KernelGuard focuses on the consequence of an attack rather than claiming to understand the prompt inside the kernel. The kernel does not parse prompts, model reasoning, or HTTPS payloads. It checks the resulting process, file, and network operations against policy.

## 2. What KernelGuard does

The canonical implementation combines:

1. **Agent execution:** a LangChain + Gemini example with a small set of registered tools.
2. **Workload identity and isolation:** the controller starts the managed workload in a dedicated cgroup v2 and registers its cgroup ID.
3. **Kernel security boundary:** eBPF programs attached through BPF-LSM inspect selected Linux security operations.
4. **Administrator-owned Zero Trust policy:** YAML policy is validated and compiled into BPF map entries by the controller.
5. **Telemetry:** BPF events are sent through a ring buffer and read in user space as JSON Lines.
6. **Behavioural research:** separate scripts extract run-level features and compare ML classifiers on a controlled dataset.
7. **Operator response:** the controller exposes observe, restrict, freeze, thaw, and kill actions for a managed workload.

The kernel policy is the synchronous enforcement authority. The ML component is advisory/offline in the current repository and must not be described as blocking a syscall.

## 3. Architecture and execution flow

```text
                ADMINISTRATOR / OPERATOR
                         |
                 Administrator YAML
                         |
                         v
                  kgctl.py controller
             validate -> load -> apply -> run
                         |
             +-----------+-----------+
             |                       |
             v                       v
       cgroup v2 identity        BPF policy maps
             |                       |
             v                       |
       LangChain + Gemini            |
          AI agent                   |
             |                       |
       registered tool               |
             |                       |
       Python subprocess              |
             |                       |
             +------ Linux operation-+
                         |
                         v
                    BPF-LSM hooks
             exec / file / network / bpf / ptrace
                         |
                  policy map lookup
                         |
                 ALLOW / AUDIT / DENY
                         |
                         v
                  BPF ring buffer
                         |
                         v
                kg_events user reader
                         |
                   JSONL events
                         |
              (separate ML research path)
                         |
              features -> model -> risk
                         |
                operator review/action
```

### Runtime sequence

1. The administrator prepares a policy file. The agent cannot edit or reload that policy.
2. `kgctl.py plan` validates the YAML and prints the intended map entries without loading BPF.
3. `kgctl.py load` loads and attaches the BPF object and pins the maps/programs.
4. `kgctl.py apply` populates maps and records the policy file's SHA-256 digest.
5. `kgctl.py run` verifies the policy digest, creates a cgroup v2 workload, registers its ID, drops the child to an unprivileged account, sets `no_new_privs`, applies configured resource limits where supported, and launches the command.
6. BPF-LSM hooks identify managed processes by the current cgroup ID and check covered operations.
7. The hook emits an event to the ring buffer. The user-space reader formats the event as JSON Lines.
8. The separate behavioural-analysis scripts can process compatible event records. A tested adapter from the current ring-buffer JSON schema to the legacy dataset schema is still required.

### Why cgroup v2 is used

A PID is not a durable workload identity: a process can fork, exit, and create descendants. KernelGuard uses a controller-created cgroup v2 directory. The controller registers its cgroup ID in a BPF map; descendants inherit cgroup membership, allowing the hooks to associate their operations with the managed workload. This is workload identity, not cryptographic proof of model identity or prompt provenance.

## 4. Repository structure

The active implementation is isolated from the research history.

```text
KernelGuard/
├── kernelguard/              # Canonical active implementation
│   ├── agent/                # LangChain + Gemini example
│   ├── bpf/                  # BPF-LSM source, shared headers, vmlinux.h
│   ├── detection/            # 23-feature extractor, ML wrapper, risk fusion
│   ├── dataset/              # Canonical dataset methodology and generators
│   ├── policy/               # Active administrator policy examples
│   ├── systemd/              # Service unit
│   ├── tests/                # Controller tests, dry-run and probes
│   ├── tools/                # Ring-buffer reader and policy linter
│   ├── kgctl.py               # Controller
│   └── Makefile
├── research/
│   ├── dataset/              # Historical controlled CSV datasets and generators
│   ├── models/               # ML training and evaluation code
│   └── results/              # Saved ML and runtime experiment outputs
├── archive/
│   ├── agents/               # Earlier agent versions and prompt-injection demo
│   ├── daemon/               # Earlier policy engines and controller
│   ├── ebpf/                 # Earlier eBPF monitor/reader experiments
│   ├── zta_v2/               # Earlier ZTA implementation snapshot
│   ├── legacy-policies/      # Earlier policy formats
│   └── legacy-scripts/       # Scripts tied to earlier directory layouts
├── docs/                     # Architecture, audit, migration and research notes
├── .github/workflows/        # Safe CI checks
├── README.md
└── .gitignore
```

The archive is retained intentionally. Historical code and scripts are not the active implementation and may require path/dependency adjustments before they can be run from the reorganised repository. The `libbpf-bootstrap` gitlink is retained separately pending confirmation of its upstream URL and submodule configuration; it must not be removed blindly.

## 5. Zero Trust policy

The active policy format is the version-1 YAML schema in `kernelguard/policy/`. The administrator owns the policy. The AI agent does not have permission to edit the policy file or BPF maps.

### Policy lifecycle

| Command | Purpose |
|---|---|
| `python3 kgctl.py doctor` | Checks kernel, BTF, cgroup v2, bpffs, bpftool and build prerequisites. |
| `python3 kgctl.py plan -p policy/policy.example.yaml` | Validates policy and previews map entries; does not load BPF. |
| `sudo python3 kgctl.py load` | Loads and attaches BPF-LSM programs and pins maps. |
| `sudo python3 kgctl.py apply -p policy/policy.example.yaml` | Applies policy entries to BPF maps and records policy SHA-256. |
| `sudo python3 kgctl.py run research_agent -- COMMAND` | Runs the managed command inside its cgroup. |
| `sudo python3 kgctl.py events` | Streams ring-buffer events as JSON Lines. |
| `sudo python3 kgctl.py status` | Shows controller state, registered agents and counters. |
| `sudo python3 kgctl.py tier research_agent restrict` | Escalates a running workload to restricted enforcement. |
| `sudo python3 kgctl.py tier research_agent freeze` | Suspends the workload; `thaw` resumes it. |
| `sudo python3 kgctl.py tier research_agent kill` | Terminates the workload cgroup. |

### Policy controls

- **Executable allow-list:** entries are resolved to device/inode identities and associated with the agent ID. Unlisted executable launches become policy violations.
- **Sensitive-file handling:** configured filename components can be denied or marked as taint sources. A tainted workload is subject to the configured egress restriction.
- **Network egress:** IPv4 destination address and port entries define the allow-list. Hostnames are resolved during policy application.
- **Self-protection:** BPF syscall and ptrace access attempts by a managed agent are treated as violations.
- **Resource limits:** cgroup PID and memory limits can constrain resource use.
- **Privilege reduction:** the controller runs the workload under a non-root account, clears supplementary groups, sets `no_new_privs`, and constructs a minimal environment.
- **Policy integrity:** the controller records a SHA-256 digest at apply time and refuses to start the workload if the policy file has changed since application.

### Audit versus enforce

- `audit`: records a policy violation but returns success from the hook; the operation is allowed to continue.
- `enforce`: records a deny event and returns `-EPERM` for the covered operation.

The example policy is configured for audit mode. Enforcement must be tested in enforce mode on a disposable VM before claiming a specific operation is blocked. A successful policy plan or BPF build is not proof of kernel enforcement.

## 6. Kernel enforcement and supported controls

The canonical BPF source contains these LSM hooks:

| Hook | Operation checked | Current policy behaviour |
|---|---|---|
| `bprm_check_security` | Executable launch | Checks device/inode/agent ID against executable allow-list. |
| `file_open` | File open | Matches the final resolved filename component against sensitive-name rules; can taint or deny. |
| `socket_connect` | Network connection | Checks IPv4 destination and port against egress allow-list when restriction applies. |
| `socket_sendmsg` | Explicit-destination send, including UDP sendto | Applies the same destination check. |
| `bpf` | BPF syscall | Treats managed-agent BPF syscall attempts as violations. |
| `ptrace_access_check` | ptrace access | Treats managed-agent ptrace access attempts as violations. |

### What attacks can be blocked?

KernelGuard does not block an abstract attack name directly. It can block a covered OS action when the action reaches a hook, the process belongs to a registered cgroup, the policy denies the operation, and enforce mode is active.

| Attack or behaviour | Current coverage | Important qualification |
|---|---|---|
| Prompt injection that causes an unapproved executable to launch | **Potentially blockable at executable boundary** | The kernel does not detect prompt injection; it can deny the resulting unlisted executable. Live LLM-driven end-to-end evidence is still needed. |
| Unauthorised `sudo` / shell launch | **Potentially blockable** | Only if the binary identity is not allow-listed and enforce mode is active. |
| Execution of an unknown binary | **Potentially blockable** | Enforced by executable allow-list for managed cgroup processes. |
| Execution from `/tmp` | **Potentially blockable** | Not a universal path rule; decision is based on executable identity/allow-list, not a generic “deny all /tmp paths” guarantee. |
| Access to configured sensitive filename components | **Potentially blockable or tainting** | Filename-component matching is not full-path/file-operation control. |
| Egress to an unlisted IPv4 address/port | **Potentially blockable** | Depends on egress restriction/taint and the relevant socket hook. |
| Agent attempts to use BPF or ptrace | **Potentially blockable** | For managed agent processes, subject to enforce mode and hook availability. |
| Fork bomb / excessive process or memory use | **Constrained** | cgroup resource limits are not a complete DoS defence. |
| IPv6 exfiltration | **Not reliably covered** | IPv6 allow-listing is not implemented; current hook does not provide a destination allow-list for IPv6. |
| HTTPS data exfiltration / malicious URL path | **Not inspected** | The system checks socket destination metadata, not encrypted request bodies or URL paths. |
| Prompt injection that abuses an already allowed executable | **Not reliably covered** | Allowing an interpreter does not sandbox its scripts or semantic intent. |
| Credential theft through an unlisted file access pattern | **Partially covered** | Only configured final filename components are matched; this is not comprehensive file-system mediation. |
| Kernel exploit, malicious kernel module, or host-root compromise | **Out of scope** | The design assumes a trusted Linux kernel and privileged controller. |
| Tool/API misuse that has no covered OS side effect | **Not covered by kernel hooks alone** | Requires application/tool-level controls and additional telemetry. |

**Safe claim:** KernelGuard implements policy checks for selected executable, file-open, network, BPF and ptrace operations. Whether a particular attack is blocked depends on its resulting OS behaviour and policy configuration. It is not a universal defence against every prompt injection, malware family, or Agentic AI attack.

## 7. Behavioural ML and dataset

### Dataset source and composition

The repository contains a controlled research-generated dataset, not a public benchmark and not real-world malware telemetry.

The documented dataset composition is:

| Class | Workload runs | Recorded events |
|---|---:|---:|
| Benign | 800 | 1,971 |
| Attack-like | 300 | 810 |
| **Total** | **1,100** | **2,781** |

Benign data consists of 40 simple task types repeated 10 times and 20 composite workflow types repeated 20 times. Attack-like data consists of 10 scripted command-sequence scenarios repeated 30 times each.

Attack-like scenario labels include `prompt_injection_sudo`, `prompt_injection_bash`, `shell_execution_chain`, `password_utility`, `tmp_executable`, `unknown_executable`, `benign_to_sudo`, `benign_to_shell`, `repeated_sudo`, and `repeated_shell`.

These labels describe controlled command sequences. The generator executes the commands directly; the labels do not prove that a live LLM received a malicious document and autonomously chose those commands.

### Data collection flow

1. Define a controlled benign or attack-like workload.
2. Prepare harmless test files and commands in a lab directory.
3. Record the current log offset and workload start time.
4. Execute the workload with timeouts.
5. Read only newly appended legacy KernelGuard log records.
6. Parse process, UID, PID, executable path, risk, reason and action.
7. Attach run ID, scenario, repetition, label and timestamps.
8. Save event-level and run-level CSV files.
9. Aggregate each run into behavioural features for model training/evaluation.

**Telemetry provenance limitation:** existing dataset generators parse the legacy text log schema (`PID | UID | PROCESS | PATH | RISK | REASON | ACTION`). The canonical `kg_events` reader emits JSON Lines from the BPF ring buffer. A tested adapter and end-to-end capture run are required before claiming the historical CSV dataset was generated from the current canonical BPF-LSM telemetry path.

### Feature extraction and ML workflow

The canonical detection feature extractor defines 23 run-level behavioural features, including:

- event count, unique processes, process changes and unique paths;
- mean and maximum path depth, dominant path ratio and path diversity;
- repetition ratio and sequence entropy;
- unique PIDs/UIDs and UID changes;
- duration, event rate and inter-event timing;
- burst count and coarse `/bin`, `/usr/bin`, `/tmp`, and `/sbin` path ratios.

The repository also contains earlier ML experiment scripts that use a larger command/category feature set (72 features in one saved report). Those earlier scripts and the canonical 23-feature inference wrapper are related but are not one fully unified, production inference pipeline.

The ML experiment compares Logistic Regression, Random Forest and Gradient Boosting. The saved outputs contain several evaluation variants; they must not be merged into one headline score.

### How ML is integrated today

- Training/evaluation scripts consume the controlled CSV dataset.
- The canonical `behavior_ml.py` loads external joblib model and feature-list artifacts and calculates a risk label.
- `risk_fusion.py` combines a ZTA decision with ML risk. A ZTA DENY remains DENY; ML risk can raise an otherwise allowed action to REVIEW.
- The model files are not included in the canonical source tree.
- The canonical controller/BPF hook does not currently call the ML wrapper synchronously.
- The data collector has not yet been validated against the canonical BPF JSON event stream.

Therefore the ML work is best described as **offline behavioural evaluation plus a reusable inference/risk-fusion module**, not a completed live ML-driven kernel enforcement integration.

## 8. Experimental results

Results are reported separately according to the saved experiment files.

### A. ML group-aware holdout evaluation

The saved report `research/results/ml_v2/ml_experiment_report.txt` describes 2,781 raw events, 1,100 run-level samples and 72 features, split into 810 training and 290 testing samples. The script uses `GroupShuffleSplit` with scenario groups and reports no group overlap for its split.

| Model | Accuracy | Precision | Recall | F1 | FPR | Avg inference |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.001187 ms |
| Random Forest | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.276802 ms |
| Gradient Boosting | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.010534 ms |

These perfect scores are results of this particular controlled split, not evidence of generalisation to real agents or unseen attack families. The dataset is small and synthetic, and features include command/path distribution signals closely related to the scripted scenario definitions. Independent datasets, live agent traces, and stronger external validation are needed.

### B. Five-fold scenario evaluation

The saved `research/results/ml/5fold/model_summary.csv` reports:

| Model | Mean accuracy | Mean precision | Mean recall | Mean F1 | Mean FPR |
|---|---:|---:|---:|---:|---:|
| Logistic Regression | 0.8336 | 0.8793 | 0.6500 | 0.6634 | 0.0482 |
| Random Forest | 0.8293 | 0.6734 | 0.8000 | 0.6820 | 0.1203 |
| Gradient Boosting | 0.7993 | 0.5876 | 0.6000 | 0.5620 | 0.1203 |

The folds show variation (for example, Random Forest accuracy standard deviation is approximately 0.0681 and Logistic Regression approximately 0.1293). This evaluation is more informative than relying only on the single perfect holdout result, but the sample remains controlled and small.

### C. Attack-wise evaluation

The saved attack-wise summary reports overall holdout accuracy of approximately 0.8264 for Logistic Regression and Random Forest, and 0.7991 for Gradient Boosting. Detection is uneven across the 10 attack-like categories: for example, the Random Forest results detect all 30 `prompt_injection_sudo` samples in that particular evaluation but miss all 30 `benign_to_shell` and `benign_to_sudo` samples. Category-specific results demonstrate that a single aggregate metric hides important failure modes.

### D. Small runtime experiment

The saved runtime experiment `research/results/final_experiment/run_20261023_233145/SUMMARY.md` records:

- Linux kernel: `6.8.0-138-generic`
- 13 test cases: 7 benign and 6 attack-oriented
- 40 KernelGuard events collected
- confusion matrix: TN=7, FP=0, FN=2, TP=4
- accuracy: 0.8462
- precision: 1.0000
- recall: 0.6667
- F1: 0.8000
- false-positive rate: 0.0000
- decisions: 5 ALLOW, 4 REVIEW, 4 DENY
- average decision/test timing: 3,724.46 µs (not pure BPF hook latency)

Four of six attack-oriented cases were classified DENY; two were REVIEW. The report explicitly states that DENY in this experiment represents the policy decision layer and should not be presented as measured kernel-level `-EPERM` enforcement. LSTM and LLM semantic adjudication were not included.

### Interpretation

The saved results show that controlled process-execution patterns can be separated to some extent by run-level features, and that the small runtime experiment produced useful policy decisions with no observed false positives in 13 cases. They do **not** establish production accuracy, robustness to adaptive attacks, or full end-to-end autonomous prompt-injection prevention. The 1.0 ML metrics should be reported alongside the lower five-fold results and the dataset limitations, not as a standalone headline.

## 9. Related work and research positioning

KernelGuard draws on established OS security and eBPF/BPF-LSM mechanisms, and on recent work that places controls around agent tool execution.

| Related direction | What it contributes | KernelGuard's relationship |
|---|---|---|
| eBPF/BPF-LSM runtime monitoring and policy enforcement | Kernel-visible process, file and network activity with low-level policy hooks. | KernelGuard uses BPF-LSM hooks and maps as its OS enforcement boundary. |
| Container/runtime eBPF + ML detection | Uses kernel telemetry to derive features and classify suspicious workloads. | KernelGuard explores run-level behavioural features for AI-agent workload traces, while retaining deterministic policy as the enforcement authority. |
| Application/tool-call policy enforcement | Intercepts tool calls and validates arguments or capabilities before execution. | KernelGuard complements this layer by checking selected resulting OS operations below the agent framework. |
| MCPGuard-Dynamic | Describes a layered MCP proxy with application validation and eBPF sandboxing for MCP server subprocesses. | Demonstrates that kernel-level eBPF controls for AI tool execution are an active research direction; KernelGuard should not claim to be the first eBPF-based AI-agent sandbox. |
| Runtime protection/sandbox approaches for LLM agents | Inspect or sandbox risky agent actions before release to the real environment. | KernelGuard takes a Linux cgroup/BPF-LSM policy approach and documents its current integration boundary. |
| Agentic AI security surveys and architectures | Systematise prompt injection, tool misuse, memory and supply-chain risks. | Help frame the threat model and clarify that OS enforcement addresses only the OS-visible part of the attack chain. |

The comparison is conceptual, not a controlled head-to-head benchmark. KernelGuard has not been evaluated against these systems using a common dataset or identical attack suite.

## 10. Research contributions and novelty

The defensible contribution is the **specific integration and evaluation of a Linux workload-scoped Zero Trust enforcement design for an Agentic AI process**, rather than a claim to invent eBPF, BPF-LSM, Zero Trust, cgroups, or ML-based anomaly detection.

Potential contributions supported by the current repository:

1. **Cgroup-scoped agent identity at the kernel boundary:** associate a controller-managed AI-agent process tree with a registered cgroup ID and use it to select policy in BPF-LSM hooks.
2. **Administrator-owned executable and resource policy:** translate YAML policy into BPF maps and combine executable identity checks with sensitive-file taint/deny, IPv4 egress restrictions, BPF/ptrace restrictions and cgroup resource limits.
3. **Deterministic enforcement separated from behavioural risk:** keep kernel policy as the final synchronous authority and treat ML as a separate advisory signal, avoiding a model call in the syscall path.
4. **Controlled behavioural dataset and evaluation:** document benign/composite and attack-like command workloads, run-level feature extraction, multiple classifiers, scenario-aware evaluation and runtime policy observations.
5. **Explicit claim boundaries and reproducibility:** distinguish scripted attack-like sequences from live LLM-driven prompt injection and distinguish saved ML scores from verified kernel blocking.

### What is not yet a demonstrated novelty claim

- The repository does not prove that KernelGuard is the first system to use eBPF for AI-agent security.
- The current saved experiments do not prove an autonomous prompt-injection attack was blocked end-to-end.
- The ML modules are not yet a tested live telemetry-to-ML-to-kernel enforcement pipeline.
- The runtime experiment does not establish kernel-level `-EPERM` blocking.
- The project has not completed a controlled head-to-head evaluation against MCPGuard-Dynamic or other related systems.

A stronger novelty claim requires a literature review, a reproducible live agent experiment, an end-to-end event adapter, enforcement-mode validation, and comparative evaluation on shared scenarios.

## 11. Attack coverage and limitations

KernelGuard can only enforce what its hooks observe and what its policy expresses. Current important limitations:

- no prompt-text, model-reasoning, or HTTPS-body inspection in the kernel;
- cgroup identity is workload identity, not cryptographic model provenance;
- sensitive-file policy matches final filename components, not full path plus operation semantics;
- network allow-list is IPv4 address/port based; IPv6 allow-listing is not implemented;
- an allowed interpreter can execute arbitrary scripts unless additional sandboxing is used;
- local UNIX-domain sockets and local service interactions are not fully mediated as network egress;
- API keys passed through environment variables are available to the agent process;
- legacy dataset collectors do not yet consume the canonical BPF ring-buffer JSON schema;
- model artifacts are external and not committed in the canonical source copy;
- BPF verifier acceptance, attach success and enforce-mode outcomes must be validated on the target kernel;
- this is a research prototype, not a production security guarantee.

## 12. Installation and safe validation

### Prerequisites

Use a disposable Ubuntu Linux VM for live BPF testing. The controller documents requirements including a compatible Linux kernel (at least 5.15), `CONFIG_BPF_LSM=y`, BPF enabled in the active LSM list, kernel BTF, cgroup v2, bpffs, bpftool, clang/LLVM with BPF target support, GCC, libbpf development headers and Python dependencies.

### Safe checks (no BPF attachment)

From the repository root:

```bash
cd kernelguard
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
```

### Build and inspect prerequisites

```bash
make
python3 kgctl.py doctor
```

A successful build or doctor check does not prove that the kernel verifier accepts the program or that the LSM program is attached and enforcing policy.

### Live test warning

Do not load, detach, or unload BPF programs on a shared host without first inspecting existing programs, links and pins and confirming ownership. Follow the test scripts and documentation in a disposable VM. Start with audit mode. Only test enforce mode with a controlled policy and verify the actual operation fails with the expected permission error. Never use a real production agent or sensitive credentials for attack tests.

## 13. Current status and future work

| Component | Repository status |
|---|---|
| Canonical BPF-LSM source and hooks | Implemented in source; target-VM verifier/attach validation still required |
| Controller and policy lifecycle | Implemented in source; clean-checkout integration testing required |
| cgroup v2 identity and resource limits | Implemented in controller source; runtime validation required |
| Ring-buffer event reader | Implemented in source; end-to-end event validation required |
| LangChain/Gemini agent example | Implemented as a controlled example |
| Controlled legacy dataset | Present with documented provenance limitations |
| ML training/evaluation scripts and saved metrics | Present in research folders |
| Canonical 23-feature extractor and inference wrapper | Present; model artifacts external |
| Risk-fusion logic | Present as an advisory decision helper |
| Live BPF JSON → dataset/ML adapter | Not yet verified |
| Live ML-triggered controller response | Not yet integrated/verified |
| Live LLM prompt-injection → kernel deny experiment | Not yet demonstrated in saved results |
| Kernel `-EPERM` enforcement in the saved runtime experiment | Not demonstrated by that experiment |

### Priority next steps

1. Run clean-checkout tests and BPF compilation on the target VM.
2. Record BPF verifier, load/attach and ring-buffer delivery results.
3. Run controlled audit and enforce-mode tests and retain the exact logs.
4. Build and test a schema adapter from BPF JSON events to the dataset feature pipeline.
5. Run a live LangChain/Gemini experiment with a benign task and a controlled malicious document; retain the document, prompt, model/tool trace, cgroup ID and kernel events.
6. Version and include model artifacts with provenance, or document a reproducible training command and artifact checksum.
7. Connect ML out-of-band risk assessment to a safe, explicit controller response workflow, with operator approval and audit logging.
8. Expand attack coverage and compare with related systems using a common benchmark.

## 14. References

The following works provide context for the problem and related approaches. They are not evidence that KernelGuard has been directly compared with those systems.

1. Meta, **MCPGuard-Dynamic: Kernel-level sandboxing for LLM agent tool calls made through the Model Context Protocol (MCP)**, project repository: https://github.com/meta/mcpguard-dynamic
2. **Runtime Protection Practice for LLM Agent Security: An On-Demand Behavioral Sandbox Approach**, IEEE conference publication, DOI: https://doi.org/10.1109/ISAEECE70502.2026.11635191
3. **Runtime Policy Enforcement for MCP-Based LLM Agents**, *Electronics*, 2026: https://www.mdpi.com/2079-9292/15/13/2829
4. **Hybrid Runtime Detection of Malicious Containers Using eBPF**, *Computers, Materials & Continua*, DOI: https://doi.org/10.32604/cmc.2025.074871
5. **Agentic AI as a Cybersecurity Attack Surface: Threats, Exploits, and Defenses in Runtime Supply Chains**, arXiv: https://arxiv.org/abs/2602.19555
6. **SafeAgent: A Runtime Protection Architecture for Agentic Systems**, arXiv: https://arxiv.org/abs/2604.17562
7. **Execute-Only Agents: Architectural Defense Against Prompt Injection for AI Agents**, Agentic OS 2026: https://os-for-agent.github.io/papers/AgenticOS_2026_paper_21.pdf

---

**Maintainer note:** New implementation work belongs under `kernelguard/`. Research datasets, model experiments and results belong under `research/`. Historical implementations belong under `archive/`. Preserve provenance and do not overwrite raw experimental outputs.
