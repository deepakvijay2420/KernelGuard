# KernelGuard

**A Linux runtime-security research prototype for constraining Agentic AI workloads.**

KernelGuard investigates how to place a deterministic operating-system security boundary around AI agents that can invoke tools, launch processes, read files, or communicate over a network. Its primary research scenario is an agent influenced by untrusted content (including indirect prompt injection) attempting an OS action outside the administrator's intended permissions.

> **Research prototype — not production-ready.** The repository contains a canonical BPF-LSM/ZTA implementation, historical experiments, a controlled behavioural dataset, ML evaluation outputs, and a small runtime experiment. The evidence does not yet establish a fully integrated live LLM → BPF telemetry → ML → automated enforcement pipeline.

## Contents

- [1. Problem and motivation](#1-problem-and-motivation)
- [2. What KernelGuard does](#2-what-kernelguard-does)
- [3. Architecture and execution flow](#3-architecture-and-execution-flow)
- [4. Repository structure](#4-repository-structure)
- [5. Zero Trust policy](#5-zero-trust-policy-the-security-contract-for-each-agent)
- [6. Kernel enforcement and supported controls](#6-kernel-enforcement-and-supported-controls)
- [7. Behavioural ML and dataset](#7-behavioural-ml-and-dataset)
- [8. Experimental results](#8-experimental-results)
- [9. Research positioning](#9-research-positioning)
- [10. Research contributions and novelty](#10-research-contributions-and-novelty)
- [11. Attack coverage and limitations](#11-attack-coverage-and-limitations)
- [12. Installation and validation plan](#12-installation-and-validation-plan)
- [13. Current status and future work](#13-current-status-and-future-work)
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

## 5. Zero Trust policy: the security contract for each agent

KernelGuard's Zero Trust policy is an administrator-owned security contract for a managed AI workload. It answers four practical questions:

1. **Who is performing the operation?** Is the current process part of a workload registered by KernelGuard?
2. **What is it trying to do?** Launch a program, open a file, connect to a destination, use BPF, or access another process through ptrace?
3. **Is that operation permitted for this workload?** Does the administrator's policy allow it?
4. **What should happen?** Allow it, record it in audit mode, or deny it in enforce mode?

The policy does not decide whether an AI prompt is malicious. It constrains selected operating-system effects that may result from the agent's decisions. The model can propose an action; the Linux kernel remains the authority that permits or rejects covered operations.

### 5.1 Trust model and security boundary

| Element | Trust decision | Responsibility |
|---|---|---|
| Administrator | Trusted policy authority | Creates, reviews and applies YAML policy; controls the privileged controller. |
| KernelGuard controller (`kgctl.py`) | Privileged enforcement setup | Validates policy, creates the managed cgroup, configures BPF maps and launches the workload with reduced privileges. |
| Managed agent process tree | Untrusted workload | May behave normally, make mistakes, or be influenced by untrusted content. It must not control its own policy. |
| Linux kernel and BPF-LSM | Trusted enforcement boundary (assumption) | Checks the covered operations at kernel security hooks. |
| User-space event reader | Telemetry consumer | Reads events from the BPF ring buffer; it is not the synchronous enforcement authority. |
| Behavioural ML | Advisory analysis in the current implementation | Analyses compatible event data out of band; it does not block a syscall in the current verified architecture. |

**Security assumptions:** the Linux kernel, privileged controller, administrator policy and host root account are trusted. KernelGuard is not designed to protect a host after kernel compromise or malicious host-root control.

### 5.2 Policy file and ownership

The canonical example is `kernelguard/policy/policy.example.yaml`. It uses schema version `1`. The administrator owns this file and the privileged BPF maps. The managed agent is launched as an unprivileged account and is not given a policy-editing or policy-application interface.

The example policy contains these top-level areas:

| YAML area | Meaning | Where it is enforced |
|---|---|---|
| `version` | Policy schema version | Controller validation |
| `sensitive.taint` | Sensitive final filename components that may be read but taint the workload | BPF `file_open` hook and per-cgroup taint state |
| `sensitive.deny` | Sensitive final filename components whose open is denied | BPF `file_open` hook |
| `agents.<name>.id` | Numeric agent identifier used in BPF policy keys | Controller and BPF maps |
| `agents.<name>.mode` | Required `audit` or `enforce` mode | BPF agent configuration |
| `run_as`, `workdir` | Unprivileged account and working directory | Controller launch process |
| `env_passthrough` | Explicit environment variables passed to the agent | Controller launch process |
| `limits` | cgroup PID and memory limits | cgroup v2 |
| `exec.allow` | Executable paths, optionally with SHA-256 pinning | Controller-resolved device/inode allow-list used by BPF |
| `network.egress_default` | Default egress behaviour: `deny` or `allow` | BPF network hooks |
| `network.allow` | Allowed IPv4 host/IP and port entries | Controller-resolved IPv4 address/port BPF map |

The policy is global for the sensitive filename lists and per-agent for the workload-specific settings. Review the actual YAML schema and the controller's validator before adding new fields; an arbitrary YAML key does not automatically become an enforced control.

### 5.3 How each policy control works

#### A. Workload identity: cgroup v2

The controller creates a dedicated cgroup v2 for the managed workload, moves the child process into it before dropping privileges, reads the cgroup directory inode (the cgroup ID), and registers that ID in the `agent_cgroups` BPF map. Child processes inherit cgroup membership.

At a BPF-LSM hook, the program calls `bpf_get_current_cgroup_id()`. If that ID is not registered, KernelGuard does not apply the agent-specific policy to that process. If it is registered, the corresponding agent configuration is used for the decision.

**Why this matters:** a PID can change as processes fork, exit or are reaped. A cgroup scopes the policy to the managed process tree rather than relying only on a single PID or process name.

**Boundary:** this identifies a managed Linux workload; it does not prove which model, prompt, user or agent framework created the process. It is not cryptographic model provenance.

#### B. Executable allow-list: `bprm_check_security`

When a managed process attempts to execute a program, the BPF-LSM `bprm_check_security` hook obtains the executable's device and inode identity and combines it with the agent ID. The `exec_allow` map is checked for that identity.

- A matching entry is allowed.
- An unlisted executable is a policy violation.
- In `audit` mode, the event is recorded and the hook returns success.
- In `enforce` mode, the violation is recorded and the hook returns `-EPERM`.

The policy's `exec.allow` entries are paths used by the controller to resolve executable identities. The optional `sha256` field can be used to pin expected binary content during policy application. The kernel hook itself makes the runtime decision using the resolved device/inode map key, not by hashing the executable at every exec.

**Why this matters:** an agent that is permitted to run Python should not automatically be permitted to launch every other executable available on the host.

**Boundary:** an allowed interpreter can still run scripts. This control is not a complete interpreter sandbox, and executable identity allow-listing alone does not understand the semantic intent of a command.

#### C. Sensitive-file policy and taint: `file_open`

The BPF-LSM `file_open` hook reads the final filename component of the resolved file being opened and checks the global `sensitive_names` map.

There are two configured actions:

- **Deny:** the open is a policy violation. Audit mode records and permits it; enforce mode returns `-EPERM`.
- **Taint:** the open is allowed, but the cgroup's runtime state is marked as having accessed a configured sensitive source.

Taint is important because a sensitive read can create a later data-exfiltration risk. The network hook checks this taint state and applies the egress allow-list to a tainted workload.

**Why this matters:** the policy can connect a sensitive data access to a later network decision instead of treating file and network activity as unrelated events.

**Boundary:** this is filename-component matching at the file-open hook, not comprehensive full-path, read/write, memory-mapping or data-flow mediation. The configured names are global rather than per-agent in the current schema. Do not describe it as universal protection for every credential file or every possible file access technique.

#### D. Network egress policy: `socket_connect` and `socket_sendmsg`

For IPv4 destinations, the hooks check destination address and port against the `egress_allow` map. The controller resolves configured hostnames when applying the policy; the kernel map contains address/port entries, not a live DNS or URL policy.

- With `egress_default: deny`, non-listed IPv4 egress is restricted for the managed workload.
- With `egress_default: allow`, ordinary egress is allowed unless the workload has been tainted by a configured sensitive-file read. A tainted workload is restricted to the explicit allow-list.
- Explicit-destination `sendmsg` traffic is checked as well as `connect` traffic. A connected socket's destination was checked at connect time.

For a restricted workload, IPv6 has no allow-list in the current implementation and is treated as unlisted. When egress is not restricted, IPv6 is not blocked by this allow-list logic.

**Why this matters:** an agent that reads a configured sensitive file can be prevented from sending traffic to arbitrary unapproved IPv4 destinations, while retaining explicitly allowed destinations such as the configured model API.

**Boundary:** the hooks inspect socket destination metadata, not DNS names at runtime, URL paths, TLS certificates, HTTP headers, HTTPS bodies or encrypted prompt content. Local UNIX-domain sockets and local service interactions are not comprehensively mediated as internet egress.

#### E. Self-protection: `bpf` and `ptrace_access_check`

For a registered agent cgroup, attempts to use the BPF syscall or ptrace access are treated as policy violations. The configured audit/enforce mode determines whether the covered operation is only recorded or denied.

**Why this matters:** a managed agent should not be able to use these powerful interfaces to interfere with kernel instrumentation or inspect other processes through ptrace.

**Boundary:** these hooks do not make the agent a fully sandboxed process and do not defend against a compromised kernel or host root.

#### F. Resource limits and privilege reduction

The controller also prepares the workload with a configured unprivileged user, clears supplementary groups, sets `no_new_privs`, uses a controlled working directory and minimal environment, and applies supported cgroup v2 PID and memory limits.

These measures reduce the impact of accidental or abusive workload behaviour. They complement, but do not replace, the BPF-LSM operation policy.

Environment variables explicitly passed through (for example, `GOOGLE_API_KEY`) become available to the agent process. This is not a secret vault and does not protect a key from the agent itself.

### 5.4 Policy lifecycle: from YAML to kernel decision

| Stage | Command / component | What happens | What it does not prove |
|---|---|---|---|
| 1. Author | Administrator edits YAML | Defines the workload's permitted operations and limits | That the policy is syntactically or semantically valid |
| 2. Plan | `python3 kgctl.py plan -p policy/policy.example.yaml` | Validates the schema and previews the intended map entries without loading BPF | That BPF is loaded or enforcing |
| 3. Load | `sudo python3 kgctl.py load` | Loads and attaches the BPF-LSM object and pins maps/programs | That every policy test passes |
| 4. Apply | `sudo python3 kgctl.py apply -p policy/policy.example.yaml` | Populates the maps and records the policy file SHA-256 digest | That every hook has been tested against real operations |
| 5. Run | `sudo python3 kgctl.py run research_agent -- COMMAND` | Verifies the applied policy digest, creates/registers the cgroup, reduces privileges and launches the command | That the agent is immune to prompt injection |
| 6. Enforce / observe | BPF-LSM hooks | Checks covered operations using the registered cgroup and BPF maps | That operations outside the listed hooks are mediated |
| 7. Monitor | `sudo python3 kgctl.py events` / `status` | Reads event stream and counters | That event collection alone proves a deny occurred |
| 8. Respond | `sudo python3 kgctl.py tier research_agent restrict` | Changes the workload to enforce mode and deny unlisted egress; other tiers include freeze, thaw and kill | That ML autonomously made this decision |

The controller also checks the policy file's SHA-256 digest at workload start. If the file changes after it was applied, the controller refuses to start the workload until the policy is reapplied. This is an integrity check on the policy file, not a digital signature or a complete protection against privileged host tampering.

### 5.5 Audit mode versus enforce mode

| Mode | Kernel hook behaviour | Appropriate use |
|---|---|---|
| `audit` | Emits an audit-deny event but returns success, so the covered operation continues | Initial rollout, learning legitimate workload behaviour and measuring false positives |
| `enforce` | Emits a deny event and returns `-EPERM` for a covered policy violation | Controlled enforcement after reviewing audit results |

The example policy deliberately uses `mode: audit`. Do not switch directly to enforce on a production or shared host. First observe legitimate activity, adjust the allow-lists, and test with harmless probes in a disposable VM.

### 5.6 Example policy, explained

The following is a shortened illustration of the actual schema. The complete runnable example is in `kernelguard/policy/policy.example.yaml`.

```yaml
version: 1

sensitive:
  taint:
    - ".env"
    - "id_rsa"
    - "credentials"
  deny:
    - "shadow"
    - "sudoers"

agents:
  research_agent:
    id: 1
    mode: audit
    run_as: kgagent
    workdir: /var/lib/kernelguard/work/research_agent

    env_passthrough:
      - GOOGLE_API_KEY

    limits:
      pids_max: 64
      memory_max: 1073741824

    exec:
      allow:
        - /usr/bin/python3
        - /usr/bin/ls
        - /usr/bin/cat

    network:
      egress_default: deny
      allow:
        - {host: generativelanguage.googleapis.com, port: 443}
        - {ip: 127.0.0.53, port: 53}
```

Interpretation:

- The managed workload is named `research_agent` and has numeric ID `1`.
- It runs in audit mode initially, so policy violations are logged but not blocked.
- It runs as the unprivileged `kgagent` user, with a dedicated working directory.
- Only the listed environment variable is passed through.
- PID and memory limits constrain resource use.
- Only executable identities resolved from the allow-list are permitted by the executable policy.
- The example restricts egress to the configured IPv4 allow-list.
- A configured taint filename is allowed to open but marks the workload tainted; after that, network egress is restricted to the allow-list.
- A configured deny filename is rejected in enforce mode.

The example includes a Gemini API hostname and a local DNS stub because the agent needs those connections in this setup. The actual resolved IP addresses can change; inspect the applied map entries and test the current environment rather than assuming a hostname is a permanent IP identity.

### 5.7 Why the ZTA policy is important for Agentic AI

Traditional application permissions often answer, "Can this user or process perform this operation?" KernelGuard adds a workload-scoped question: "Should this particular managed agent workload be allowed to perform this operation under its administrator-defined policy?"

This matters because:

- **Agent decisions are dynamic.** The agent may select different tools and launch child processes depending on user requests or untrusted context.
- **Prompt safety is not an OS boundary.** A model can be influenced even when the operating system still needs to protect files, executables and network destinations.
- **Permissions should be least-privilege.** The agent receives only the executable and egress capabilities that the administrator explicitly configures.
- **Policy is independent of model reasoning.** The kernel checks the resulting operation without needing to understand the prompt or call another LLM.
- **Sensitive access can influence later egress.** The taint mechanism links selected sensitive-file opens to network restrictions.
- **Audit-first rollout is measurable.** Administrators can observe legitimate activity before enabling enforcement.

### 5.8 Defensible research novelty

KernelGuard does not claim to invent Zero Trust, eBPF, BPF-LSM, cgroups or ML anomaly detection. Its research contribution is the design and evaluation of their specific combination for a managed Agentic AI workload:

1. **Workload-scoped identity:** cgroup v2 identity is used at the kernel boundary to select the policy for an agent process tree.
2. **Administrator-owned policy translation:** a versioned YAML policy is validated and translated into BPF map entries rather than being delegated to the agent.
3. **Operation-level enforcement:** BPF-LSM hooks constrain selected executable, sensitive-file, network, BPF and ptrace operations resulting from agent activity.
4. **Cross-operation taint-to-egress control:** a configured sensitive-file open can taint the workload and cause subsequent non-allow-listed egress to be denied when egress is restricted.
5. **Deterministic enforcement separated from ML:** the kernel policy remains the synchronous authority; behavioural ML is kept out of the syscall path and is advisory in the current implementation.
6. **Explicit, testable claim boundaries:** evaluation distinguishes policy decisions, telemetry, audit events and actual kernel `-EPERM` denials.

**Research contribution statement:** KernelGuard investigates a workload-scoped Zero Trust enforcement framework for Linux-based Agentic AI applications. It combines cgroup v2 workload identity, administrator-defined YAML policy, BPF-LSM checks on selected operating-system operations, and a sensitive-read-to-egress restriction mechanism. Its purpose is to constrain OS-visible consequences of potentially manipulated agent behaviour independently of the agent's prompt-level reasoning.

This is a defensible contribution statement, not a claim of being the first eBPF-based AI security system. The strength of the novelty claim depends on reproducible experiments demonstrating the integrated behaviour.

### 5.9 Threat coverage: what the policy can and cannot do

| Scenario | Current coverage | Conditions / limitation |
|---|---|---|
| Prompt injection leads to launch of an unlisted executable | Potentially blockable | The kernel does not detect the prompt; the resulting exec must be covered, the process must be in the registered cgroup and enforce mode must be active. |
| Agent attempts to launch `sudo`, shell or another unlisted binary | Potentially blockable | Depends on the executable identity not being allow-listed. |
| Agent opens a configured sensitive filename in the deny list | Potentially blockable | Final filename component must match; enforce mode must be active. |
| Agent opens a configured taint filename | Taint and later egress restriction | Open is allowed; subsequent non-allow-listed egress is restricted when the egress policy is configured to restrict. |
| Agent connects to an unlisted IPv4 destination/port | Potentially blockable | Depends on `egress_default` or taint state and enforce mode. |
| Agent attempts BPF or ptrace access | Potentially blockable | Managed cgroup and enforce mode required. |
| Excessive process or memory use | Resource constrained | cgroup limits help; they are not a complete denial-of-service defence. |
| IPv6 egress | Partial / no allow-list | Restricted workloads treat IPv6 as unlisted; unrestricted workloads are not blocked by this allow-list logic. |
| HTTPS body, URL path or prompt content inspection | Not implemented | Socket destination metadata is checked, not encrypted application payloads. |
| Malicious script executed by an allowed interpreter | Not comprehensively covered | Executable allow-listing does not sandbox interpreter input or script semantics. |
| Every possible credential access or data leak | Not guaranteed | File matching is limited; other access paths and local IPC are not comprehensively mediated. |
| Kernel compromise or malicious host root | Out of scope | KernelGuard assumes a trusted kernel and privileged controller. |

**Correct interpretation:** KernelGuard does not block the label "prompt injection" directly. It can deny selected operating-system actions that result from an agent's behaviour, provided the action reaches a covered hook and the active policy denies it.

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

The policy controls and their limitations are described in detail in Section 5. A hook being present in source code is not by itself evidence that it loaded, attached or successfully denied an operation on the target kernel.

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

## 9. Research positioning

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

## 12. Installation and validation plan

### 12.1 Prerequisites

Use a disposable Ubuntu Linux VM for live BPF testing. The controller documents requirements including a compatible Linux kernel (at least 5.15), `CONFIG_BPF_LSM=y`, BPF enabled in the active LSM list, kernel BTF, cgroup v2, bpffs, bpftool, clang/LLVM with BPF target support, GCC, libbpf development headers and Python dependencies.

### 12.2 Stage 1 — safe, non-privileged checks

From the repository root:

```bash
cd kernelguard
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
```

These checks validate the policy/controller and safe test paths. They do not establish BPF verifier acceptance, attachment or kernel enforcement.

### 12.3 Stage 2 — inspect kernel prerequisites and build

```bash
uname -r
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
mount | grep cgroup
mount | grep bpf

make
python3 kgctl.py doctor
```

Record the kernel version, BPF-LSM configuration, active LSM list, cgroup v2 and bpffs state, BTF availability, build output and doctor output. Confirm that `bpf` is in the active LSM list. A successful compile or doctor check is not proof that the verifier accepted and attached every hook.

### 12.4 Stage 3 — audit-mode baseline

1. Keep `mode: audit` in the test policy.
2. Load the BPF object and apply the policy only in the disposable VM.
3. Run a benign agent task through `kgctl.py run`.
4. Observe the event stream and status counters.
5. Record legitimate executable, file and network activity.
6. Adjust the allow-lists only when the operation is understood and required.

Example commands (check `--help` and the current VM state before use):

```bash
sudo python3 kgctl.py load
sudo python3 kgctl.py apply -p policy/policy.example.yaml
sudo python3 kgctl.py events
```

Run the managed workload from another terminal using the configured agent name and command. Stop the event reader cleanly after collecting the test. Preserve the exact policy file used and its SHA-256 digest with the experiment.

### 12.5 Stage 4 — controlled enforcement probes

Use harmless files, binaries and local test services. Do not test against production credentials, real sensitive files, external third-party systems or a shared host.

| Test ID | Controlled action | Expected audit-mode result | Expected enforce-mode result | Evidence to retain |
|---|---|---|---|---|
| ZTA-01 | Launch an allow-listed executable from the managed cgroup | Allowed; no policy violation | Allowed | Process exit status, cgroup ID, event/counter |
| ZTA-02 | Attempt to launch a deliberately unlisted harmless executable | Audit-deny event; operation continues | Deny event; operation fails with `EPERM` | Exact command, exit status, hook event and counter |
| ZTA-03 | Open a harmless test file whose final name is configured under `sensitive.deny` | Audit-deny event; open continues | Deny event; open fails with `EPERM` | Test filename, policy, open result, hook event |
| ZTA-04 | Open a harmless file configured under `sensitive.taint` | Taint event; open succeeds | Taint event; open succeeds | Taint event and agent state |
| ZTA-05 | After ZTA-04, connect to a non-allow-listed IPv4 test destination | If restricted by egress policy, audit-deny event; connection continues | Deny event; connection fails | Destination/port, taint state, socket hook event |
| ZTA-06 | Connect to an explicitly allow-listed IPv4 test destination | Allowed | Allowed | Destination/port and connection result |
| ZTA-07 | Attempt BPF syscall from the managed workload | Audit-deny event; syscall continues if otherwise permitted | Deny event; syscall fails | Probe result and BPF hook event |
| ZTA-08 | Attempt ptrace access in a controlled test | Audit-deny event; syscall continues if otherwise permitted | Deny event; syscall fails | Probe result and ptrace hook event |
| ZTA-09 | Run an unmanaged process and repeat a restricted test operation | Agent-specific policy does not apply | Agent-specific policy does not apply | Managed/unmanaged cgroup IDs and results |
| ZTA-10 | Exceed a deliberately small test PID or memory limit | cgroup limit constrains workload | cgroup limit constrains workload | cgroup configuration and kernel/cgroup result |

For every test, verify all four parts: (1) the process is in the intended cgroup, (2) the expected map/policy is applied, (3) the relevant hook event or counter is observed, and (4) the actual operation result matches the expected verdict. A log message alone is insufficient proof of blocking.

**Audit/enforce comparison:** use the same benign test workload, same OS permissions, same policy entries and same operation in both modes. Change only the mode. Audit should record the violation while allowing the covered operation; enforce should record the denial and cause the covered operation to fail. If the operation fails for an unrelated Linux permission, missing file, network outage or configuration error, it is not evidence of KernelGuard enforcement.

### 12.6 Stage 5 — prompt-injection-to-OS-action experiment

This is the central research experiment, and it must be distinguished from a direct syscall probe.

**Baseline run:** execute the same agent and task without KernelGuard enforcement. Supply a controlled test document containing an instruction that attempts to induce a prohibited but harmless test action. Record whether the model actually chooses the tool/action.

**Protected run:** execute the same agent, task, model configuration, document and host permissions inside the KernelGuard-managed cgroup with the relevant policy in enforce mode. Record the agent/tool trace, attempted OS operation, cgroup ID, BPF event, policy verdict and actual operation result.

Keep the workload and test conditions identical except for the KernelGuard enforcement condition. If the agent does not attempt the operation, the experiment cannot be used to claim that KernelGuard blocked it. In that case, report the direct controlled hook probe separately.

Evidence package:
- benign task and malicious test document (sanitised);
- exact agent configuration and tool trace;
- policy YAML and SHA-256 digest;
- kernel version and BPF-LSM configuration;
- agent PID and cgroup ID;
- event-reader output and relevant counters;
- operation exit status and error;
- repeat count, timestamp and test environment.

### 12.7 Stage 6 — quantify enforcement

Report results from repeated trials rather than one screenshot.

```text
Blocking rate = blocked prohibited attempts / total prohibited attempts * 100
False denial rate = legitimate attempts incorrectly blocked / total legitimate attempts * 100
```

Also report:
- legitimate-operation success rate;
- policy validation pass/fail counts;
- workload identity correctness;
- event delivery/loss, if measurable;
- decision and enforcement overhead, with the timing boundary clearly stated;
- per-hook and per-scenario results, not only one aggregate score.

For latency, distinguish BPF hook execution time, user-space event processing time and end-to-end operation time. Do not label a full decision/test duration as pure BPF hook latency.

### 12.8 Validation evidence checklist

| Evidence | Required to claim |
|---|---|
| Policy plan output and invalid-policy tests | Policy parser/validator behaviour |
| cgroup membership and registered cgroup map entry | Workload-scoped identity |
| BPF verifier/load/attach logs and pinned program/map inspection | BPF program loaded and attached |
| Ring-buffer event plus matching counter | Hook observed the operation and telemetry was delivered |
| Audit operation succeeds with audit-deny event | Audit mode records without blocking |
| Enforce operation fails with `EPERM`, matching deny event and counter | Kernel-level denial for that specific covered operation |
| Managed/unmanaged comparison | Agent policy is scoped to registered workload |
| Same live agent task in baseline/protected runs | End-to-end prompt-injection scenario, but only if the agent actually attempts the action |
| Repeated benign and prohibited trials | Measured blocking and false-denial rates |

### 12.9 Safety notes

Do not load, detach or unload BPF programs on a shared host without first inspecting existing programs, links and pins and confirming ownership. Follow the test scripts and documentation in a disposable VM. Start with audit mode. Only test enforce mode with a controlled policy and verify the actual operation fails with the expected permission error. Never use a real production agent or sensitive credentials for attack tests.

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

**Maintainer note:** New implementation work belongs under `kernelguard/`. Research datasets, model experiments and results belong under `research/`. Historical implementations belong under `archive/`. Preserve provenance and do not overwrite raw experimental outputs.
