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
- [Live demonstration guide](docs/LIVE_DEMO_GUIDE.md)
- [Latest implementation and verified progress](#13-latest-implementation-and-verified-progress)
- [Current status and future work](#14-current-status-and-future-work)
- [References](#15-references)
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

### 12.1 Tested development environment

The project has been developed and exercised on Ubuntu 22.04 with a Linux 6.8 kernel. The exact host configuration must be checked on the machine used for review; kernel configuration and installed packages vary.

### 12.2 Prerequisites

The active implementation requires:

- Linux kernel 5.15 or newer with BPF support, `CONFIG_BPF_LSM=y`, and `bpf` enabled in the active LSM list;
- kernel BTF at `/sys/kernel/btf/vmlinux`;
- cgroup v2 and bpffs;
- Clang/LLVM with the BPF target, GCC, Make, bpftool, libbpf development headers and kernel headers;
- Python 3.10+ and PyYAML for controller and policy operations.

Install the common Ubuntu packages:

```bash
sudo apt update
sudo apt install -y clang llvm gcc make pkg-config libbpf-dev bpftool \
  linux-headers-$(uname -r) python3 python3-venv python3-pip
```

Confirm the active Linux security modules and cgroup filesystem before attempting a live load:

```bash
uname -r
cat /sys/kernel/security/lsm
mount | grep -E 'bpf|cgroup2'
test -r /sys/kernel/btf/vmlinux && echo "Kernel BTF available"
```

### 12.3 Clone and install Python dependency

```bash
git clone https://github.com/deepakvijay2420/KernelGuard.git
cd KernelGuard/kernelguard
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install PyYAML
```

The optional ML modules use additional packages such as NumPy, pandas and joblib; the optional Gemini agent requires LangChain, the Google GenAI integration and a user-provided API key. These optional dependencies are not required for controller unit tests or policy dry-run.

### 12.4 Safe quick-start (no root, no BPF attachment)

Start with checks that do not load or unload kernel programs:

```bash
cd KernelGuard/kernelguard
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
```

The dry-run performs Python/shell syntax checks, validates example policies and runs unit tests. It does not create cgroups, change BPF maps, attach programs or prove runtime enforcement.

### 12.5 Build

```bash
cd KernelGuard/kernelguard
make
```

The Makefile builds:

- `build/kg_zta.bpf.o`: the BPF-LSM object;
- `build/kg_events`: the userspace ring-buffer reader.

If the BPF build reports a missing or incompatible `bpf/vmlinux.h`, regenerate it only after confirming the target kernel BTF is available:

```bash
make vmlinux
make
```

### 12.6 Live operation (disposable VM only)

Live operation requires root and a supported kernel. Before loading anything, inspect existing BPF links and pins. Do not run load/unload commands on a shared host or a machine with other BPF workloads unless ownership is confirmed.

After reviewing the policy and confirming the machine is a disposable test VM:

```bash
sudo python3 kgctl.py doctor
sudo python3 kgctl.py load
sudo python3 kgctl.py apply -p policy/policy.example.yaml
sudo python3 kgctl.py status
```

The example policy uses **audit** mode. Audit mode records would-be denials but permits the operation. For a live workload, use the controller form:

```bash
sudo python3 kgctl.py run research_agent -- /usr/bin/python3 --version
```

For the event stream, use a separate terminal:

```bash
sudo python3 kgctl.py events
```

The command and output depend on the active policy, user account, kernel configuration and installed binary paths. Do not change the example to enforce mode until legitimate operations have been observed in audit mode and the policy has been reviewed.

### 12.7 Optional LangChain + Gemini agent

The example agent is under `kernelguard/agent/langchain_gemini_agent.py`. It calls an external Gemini API and therefore needs network access, compatible Python packages and a valid API key. Never commit the key. Configure it as an environment variable in the controlled agent environment, consistent with the policy's `env_passthrough`.

An external model API failure (rate limit, service unavailable, invalid key or denied egress) is not evidence of a KernelGuard kernel failure. For a deterministic code review, first demonstrate the local controlled executable and file tests; treat the live LLM call as an optional integration demonstration.

### 12.8 Unload

Only unload KernelGuard programs from the same disposable VM where you loaded them, after confirming that the pinned objects belong to this test instance:

```bash
sudo python3 kgctl.py unload
```

### 12.9 What each validation result proves

| Check | What it proves | What it does not prove |
|---|---|---|
| `kgctl.py plan` | Policy parses and planned map entries can be generated | BPF is loaded or enforcing |
| `make test` | Controller validation and data-layout unit tests pass | Kernel verifier/attach succeeds |
| `make` | BPF object and userspace reader compile on this machine | BPF object loads or emits valid events |
| `kgctl.py doctor` | Reported kernel/runtime prerequisites | Every hook enforces the intended policy |
| Audit-mode test | Covered actions produce audit decisions | The kernel blocks those actions |
| Enforce-mode test plus observed `EPERM` | A specific tested operation was blocked in that environment | All attack classes are blocked |

## 13. Latest implementation and verified progress

The following status is based on the Ubuntu source snapshot supplied for review on 19 November 2026, including the `KernelGuard-Core/` working copy and its saved stage reports. It is important to distinguish that local snapshot from the older controller currently present under the canonical GitHub path until the source synchronization is reviewed and merged.

### Implemented and evidenced in the latest Ubuntu snapshot

| Area | Current implementation / evidence | Status boundary |
|---|---|---|
| eBPF-LSM runtime controls | BPF-LSM hooks for executable checks, sensitive file opens, selected network operations, and BPF/ptrace-related restrictions | Implemented in source; selected hook behaviours have runtime evidence, not universal syscall coverage |
| Workload identity | Dedicated cgroup v2 per managed agent; cgroup ID is used as the workload identity key in BPF maps | Demonstrated in the saved stage reports |
| Executable policy | Per-agent executable allow-list based on the executable file identity (device/inode) | Enforce-mode denial of an unapproved `/usr/bin/id` is recorded with `EPERM` |
| Sensitive file policy | Configurable filename rules; a synthetic `.env` read can taint a workload and a synthetic `shadow` filename can be denied | Taint and denial events are recorded in Stage 5; these tests use synthetic files, not real system secrets |
| Taint-based egress | A tainted workload's selected IPv4 network connection is checked against the egress allow-list | Stage 5 records denial of a connection to `1.1.1.1:443` after a synthetic `.env` read |
| Audit/enforce modes | Audit mode records a would-deny decision while allowing the operation; enforce mode rejects the tested operation | Stage 3 and Stage 5 reports distinguish audit from enforce outcomes |
| cgroup resource limits | Controller checks configured cgroup controllers, writes configured limits and reads values back | Latest Core controller adds fail-closed validation; the controller source must be synchronized into the canonical path |
| Process lifecycle | Controller terminates remaining descendants and removes BPF identity/run state only after confirming the cgroup is empty | Latest Core controller adds lifecycle hardening; unit tests pass, but failure-path runtime testing should continue |
| Event telemetry | Ring-buffer reader emits structured JSON Lines with cgroup ID, agent ID, hook, verdict, process and target fields | Runtime event records are present in supplied evidence |
| LangChain/Gemini agent | A controlled agent example and prompt-injection experiment scripts/evidence are present | External API availability and repeatability are environment-dependent; not a prerequisite for the deterministic kernel demo |

### Latest saved runtime evidence

The supplied Stage 3 report records 30 controller unit tests passing. It also records an audit-mode test where an unapproved executable was logged as `audit_deny` and allowed to run, followed by an enforce-mode test where the same unapproved `/usr/bin/id` operation was denied and returned exit code 126 with an `EPERM` message.

The supplied Stage 5 report records these outcomes under an enforce policy:

- A normal synthetic public-file read completed.
- Reading a synthetic `.env` file generated a `file_open / taint` event.
- Reading a synthetic file named `shadow` generated a `file_open / deny` event and `Operation not permitted`.
- After the synthetic `.env` read, a connection attempt to `1.1.1.1:443` generated a `connect / deny` event and `PermissionError`.
- The report records the agent workload cgroup IDs and event details. These are test results from the supplied VM reports, not a guarantee for every kernel or policy configuration.

The separate enforcement report records an authorized `/usr/bin/whoami` run succeeding and an unapproved `/usr/bin/id` run being refused in enforce mode. Keep the raw reports in the repository as evidence; do not turn these finite tests into a claim of complete attack prevention.

### Behavioural ML: what is implemented and what is not

The project has ML research code; it is not accurate to say that no ML work has been done. The current work includes controlled dataset generation, run-level feature extraction, training/evaluation scripts for Logistic Regression, Random Forest and Gradient Boosting, saved experiment results, a model-loading/inference wrapper, and an advisory risk-fusion helper.

However, the current evidence does **not** establish a fully integrated live pipeline in which current BPF ring-buffer JSON is continuously converted to ML features, scored by a deployed model, and used to trigger an automated controller response. The saved controlled-dataset results and saved runtime decision experiment must remain separate from live kernel enforcement evidence. LSTM autoencoder inference and LLM semantic adjudication are not demonstrated as completed components in the supplied implementation snapshot.

### Remaining work (not to be presented as completed)

1. Synchronize the latest hardened `KernelGuard-Core/kgctl.py` into the canonical `kernelguard/kgctl.py` path and retain the existing repository history.
2. Run the complete test suite and BPF build from a clean checkout of the canonical layout.
3. Validate BPF verifier acceptance, load/attach, event delivery and enforce-mode behaviour on the target Ubuntu VM after synchronization.
4. Expand tests for cgroup controller failures, descendants, interrupted workloads and cleanup failure paths.
5. Build and validate the BPF JSON-to-dataset adapter before claiming current telemetry feeds the ML pipeline.
6. Reproduce ML experiments from the documented dataset and record artifact provenance/checksums; keep offline evaluation separate from runtime detection claims.
7. If live ML response is pursued, integrate it out-of-band with explicit operator policy, bounded response actions and audit logging.
8. Re-run the guide demonstration from a clean checkout and archive command output, policy hash and event logs.

## 14. Current status and future work

KernelGuard is an active research prototype with demonstrated selected kernel-level enforcement on the supplied Ubuntu VM. It is not production-ready and does not claim universal prompt-injection detection or a fully integrated ML-driven enforcement pipeline. The canonical GitHub source still requires the controller synchronization and clean-checkout validation listed above before the repository can be called fully up to date.

## 15. References

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
