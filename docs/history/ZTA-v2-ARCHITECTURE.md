# KernelGuard — Complete Code Architecture and Execution Guide

> **Purpose:** This document explains how the current repository is organised, what each major component does, how an AI agent uses the Gemini API, and how the ZTA v2 eBPF enforcement path works.
>
> **Scope and accuracy:** The repository contains legacy/v1 monitoring code, agent examples, dataset/ML experiments, and the newer `zta_v2` enforcement implementation. These are related project components, but they are **not all one automatically connected runtime pipeline**. This guide distinguishes implemented code from integration assumptions and limitations.

## 1. KernelGuard in one view

KernelGuard is a Linux runtime security research prototype for Agentic AI workloads. An AI agent can call tools; those tools may execute programs, open files, or make network requests. KernelGuard aims to restrict selected operating-system actions even if the agent is influenced by untrusted instructions.

The main ZTA v2 idea is:

1. An administrator writes a YAML policy.
2. The controller validates the policy and translates it into BPF map entries.
3. The controller launches the agent in a dedicated Linux cgroup v2.
4. When the agent or one of its child processes performs a monitored operation, Linux invokes the relevant BPF-LSM hook.
5. The hook identifies the workload by its cgroup ID, checks the policy maps, and allows or rejects the operation.
6. The hook publishes a decision event to a BPF ring buffer.
7. A user-space reader converts the event into JSON for monitoring and evaluation.

**Important:** the kernel makes the allow/deny decision. The ring buffer only reports the decision; it is not the enforcement engine.

## 2. Repository structure

The repository has several generations and workstreams. The following is a functional map of the important paths present in the project.

```text
KernelGuard/
├── agents/
│   ├── langchain_agent/
│   │   ├── agent.py
│   │   ├── kernelguard_gemini_agent.py
│   │   ├── kernelguard_agent.py
│   │   ├── kernelguard_final_agent.py
│   │   └── run_*.sh
│   ├── prompt_injection_demo/
│   ├── malicious_agent.py
│   └── tools.py
│
├── ebpf/
│   ├── exec_monitor.bpf.c
│   ├── exec_monitor.c
│   ├── kernelguard_reader.c
│   └── zta/
│
├── daemon/
│   ├── policy_engine.py
│   ├── dynamic_policy_engine.py
│   └── zta/zta_controller.c
│
├── policies/
│   ├── agent_policy.yaml
│   └── policy.yaml
│
├── model/
│   ├── behavior_features.py
│   ├── behavior_ml.py
│   ├── risk_fusion.py
│   ├── train_final_behavior_model.py
│   └── evaluation scripts
│
├── dataset/
│   └── ml_v2/
│       ├── generators/
│       ├── benign/
│       ├── attacks/
│       └── README.md
│
├── results/
│   ├── ml/
│   ├── ml_v2/
│   └── final_experiment/
│
└── zta_v2/
    ├── bpf/
    │   ├── kg_zta.bpf.c
    │   ├── kg_common.h
    │   └── vmlinux.h
    ├── tools/
    │   └── kg_events.c
    ├── policy/
    │   ├── policy.example.yaml
    │   ├── policy.hardened.yaml
    │   └── dangerous_commands.yaml
    ├── tests/
    │   ├── test_kgctl.py
    │   ├── dry_run.sh
    │   ├── attack_probe.py
    │   └── policy.test.yaml
    ├── systemd/
    │   └── kernelguard-zta.service
    ├── kgctl.py
    ├── Makefile
    ├── README.md
    └── ARCHITECTURE.md
```

### What the top-level folders are for

| Folder | Role |
|---|---|
| `agents/` | LangChain/Gemini agent examples, tool definitions, and experiment launch scripts. This is the AI application layer. |
| `ebpf/` | Earlier eBPF execution-monitoring and reader code, plus older ZTA-related code. Do not confuse it with the current `zta_v2/bpf/` implementation. |
| `daemon/` | Earlier user-space policy-engine and controller experiments. |
| `policies/` | Policy examples used by earlier project versions. The current v2 example is under `zta_v2/policy/`. |
| `model/` | Feature extraction, ML training/evaluation, and risk-fusion experiments. |
| `dataset/` | Benign and attack-like event collection scripts and generated CSV datasets. |
| `results/` | Saved experiment outputs, metrics, and reports. |
| `zta_v2/` | The newer controller-managed BPF-LSM Zero Trust enforcement prototype described in detail below. |

## 3. The AI agent layer

### 3.1 What an agent does

The example in `agents/langchain_agent/kernelguard_gemini_agent.py` creates a LangChain agent backed by Google's Gemini model. It registers two tools:

- `list_files()`: runs `ls -la` on the configured test directory and returns the output.
- `read_research_file()`: runs `cat` on the configured `research.txt` file and returns its contents.

The agent is created with `create_agent(model=model, tools=[...], system_prompt=SYSTEM_PROMPT)`. When `agent.invoke(...)` is called, LangChain sends the user task to the model. The model can respond directly or request one of the registered tools. LangChain runs the selected tool and supplies its output back to the model; the model then produces the final response.

The system prompt tells the model to use only the supplied tools and stay within the test directory. This is an application-level instruction, not a kernel security boundary. A prompt can be ignored or manipulated; operating-system restrictions must therefore be enforced separately.

### 3.2 Gemini model and API key

The example constructs the model as:

```python
model = ChatGoogleGenerativeAI(
    model="gemini-3.8-flash",
    temperature=0,
)
```

There is no API key literal or `api_key=` argument in this constructor. The Google GenAI LangChain integration obtains its credential from the process environment, normally the `GOOGLE_API_KEY` environment variable.

The intended credential path in the v2 example policy is:

1. The operator supplies `GOOGLE_API_KEY` to the environment in which the KernelGuard controller is started.
2. The YAML `env_passthrough` list names `GOOGLE_API_KEY`.
3. In `kgctl.py run`, the controller creates a minimal child-process environment. It copies only variables named in `env_passthrough` when those variables exist in the controller's own environment.
4. The agent process receives `GOOGLE_API_KEY`.
5. `ChatGoogleGenerativeAI` reads the variable when it initializes/uses the Gemini client.
6. The client makes HTTPS requests to Google's Gemini API. The API key authenticates those requests.

The key is **not** placed in the YAML policy, compiled into the BPF program, or stored in a BPF map by this implementation. The policy contains only the variable name.

**Security warning:** passing an API key to an agent means that agent process can use it. Environment filtering is not a secret vault. Do not hard-code the key, commit it to Git, print it in logs, or include its value in screenshots. Use a dedicated, scoped key and rotate it if exposed.

### 3.3 What happens to a tool call

For example, when the model selects `read_research_file`:

1. LangChain invokes the Python tool function.
2. The function calls `subprocess.run(["cat", file_path], ...)`.
3. Linux attempts to execute the `cat` binary.
4. If the agent is running inside the v2 cgroup, the `bprm_check_security` hook checks whether that executable is allow-listed for the agent.
5. If execution is allowed, `cat` attempts to open the file.
6. The `file_open` hook checks whether the final filename component appears in the configured sensitive-file map.
7. The tool returns stdout/stderr to LangChain; the model uses that result to form its answer.

The Python tool code itself does not call `kgctl.py`. The controller must launch the Python agent process for it to be placed inside the managed cgroup. The example agent's test directory and the policy's configured work directory are separate settings; they must be made consistent for a real experiment.

## 4. ZTA v2 components — detailed code responsibilities

### 4.1 `zta_v2/policy/policy.example.yaml`

This is the administrator-authored policy input. It describes:

- Agent ID and mode (`audit` or `enforce`).
- The unprivileged Linux account (`run_as`).
- The agent working directory (`workdir`).
- Environment variables that may be passed to the agent (`env_passthrough`).
- Process and memory limits.
- Executables permitted to launch.
- Sensitive filename components that cause taint or denial.
- Network destinations and ports that are allowed.

The policy is configuration, not executable code. The model does not generate or approve these rules. The example currently uses `mode: audit`, so policy violations are logged but allowed. Blocking requires an enforce-mode run and appropriate runtime validation.

### 4.2 `zta_v2/kgctl.py` — the controller

This is the user-space control plane. It is responsible for preparing the workload and configuring the kernel enforcement program.

| Function / command | What it does |
|---|---|
| `load_policy()` | Reads the YAML file. |
| `validate_policy()` | Checks required fields, agent IDs, modes, executable entries, network entries, limits, and sensitive filenames. |
| `_resolve_exec()` | Resolves each executable path, checks that it is a regular executable file, and optionally verifies its SHA-256. |
| `build_plan()` | Converts policy values into the byte keys/values expected by BPF maps. Resolves hostnames to IPv4 addresses during policy application. |
| `doctor` | Checks kernel/configuration prerequisites, BTF, cgroup v2, bpffs, bpftool, and expected build artifacts. It does not prove successful live enforcement. |
| `plan` | Validates and prints the planned map entries without loading BPF programs. |
| `load` | Uses bpftool to load the compiled BPF object, pin its maps/programs, and auto-attach the LSM programs. |
| `apply` | Writes policy entries into pinned BPF maps and saves policy state plus the policy SHA-256. |
| `run` | Verifies that the policy has not changed, prepares the agent cgroup, registers its cgroup ID in a BPF map, drops privileges, and launches the command. |
| `tier` | Provides observe/restrict/freeze/thaw/kill responses for a managed agent. |
| `status` | Displays loaded state, active agent runs, and available hook/verdict counters. |
| `events` | Starts the JSON event reader. |
| `unload` | Removes the controller's pinned program/map links. Use only after confirming ownership and that no managed agents remain. |

#### How the controller identifies an agent

The controller creates a directory under the cgroup v2 hierarchy. On cgroup v2, the cgroup directory inode number is used as the cgroup ID. The controller inserts that ID into the `agent_cgroups` BPF map along with the numeric agent ID, mode, and network-default setting.

The kernel hook calls `bpf_get_current_cgroup_id()` and looks up that value. If it is not registered, the hook returns without applying KernelGuard's agent-specific policy. Child processes inherit their parent's cgroup membership, so the policy follows the workload's child processes.

This identifies the managed workload; it does not cryptographically identify the model, prompt, or individual LangChain tool call.

#### How the controller starts the workload

The `run` path:

1. Confirms that a policy was applied and its SHA-256 has not changed.
2. Re-loads and validates the policy and rechecks executable entries.
3. Resolves the configured unprivileged Linux account and refuses UID 0.
4. Creates/chowns the configured working directory.
5. Builds a minimal environment containing a restricted PATH, HOME, locale, agent/workdir metadata, and only explicitly passed-through variables.
6. Creates a dedicated cgroup and attempts to set `pids.max` and `memory.max`.
7. Registers the cgroup ID and agent configuration in `agent_cgroups`.
8. Forks. The child joins the cgroup while privileged, clears supplementary groups, changes GID/UID, sets `no_new_privs`, changes directory, and executes the requested command.
9. The parent waits for the workload, cleans up the cgroup registration and runtime state after it exits.

Cgroup resource limits are Linux cgroup controls, not BPF-LSM hooks. The controller warns if it cannot set a requested limit; the actual cgroup files should be checked during testing.

### 4.3 `zta_v2/bpf/kg_zta.bpf.c` — kernel enforcement

This is the main eBPF program. It contains BPF-LSM hooks that run at selected Linux security decision points. Each hook first checks whether the current process belongs to a registered agent cgroup. If not, it leaves the operation to the rest of Linux.

The current hooks are:

| BPF-LSM hook | Trigger | Policy check |
|---|---|---|
| `bprm_check_security` | A process attempts to execute a binary | Looks up executable device/inode plus agent ID in `exec_allow`. An unlisted executable is a violation. |
| `file_open` | A process opens a file | Reads the resolved file's final name component and checks `sensitive_names`. A taint entry marks the agent; a deny entry is a violation. |
| `socket_connect` | A process attempts a socket connection | Checks IPv4 destination address and port against `egress_allow`. |
| `socket_sendmsg` | A process sends a message with an explicit destination, such as UDP sendto | Checks the destination using the same egress policy. |
| `bpf` | A process invokes the `bpf()` system call | Treats an agent's call as a policy violation. |
| `ptrace_access_check` | A process requests ptrace access | Treats an agent-initiated ptrace access check as a policy violation. |

#### Audit versus enforce

The common `violation()` helper selects the result:

- In `audit` mode, it emits an `audit_deny` event but returns success to the kernel, so the operation is allowed.
- In `enforce` mode, it emits a `deny` event and returns `-EPERM`, rejecting the operation.

An earlier LSM denial is preserved: the hook returns an existing non-zero `ret` rather than overriding it.

#### Sensitive-file taint

A taint match does not deny the file open. It sets a taint flag in `agent_state` for that cgroup and emits a taint event. Later network checks consider the agent restricted if either `egress_default_deny` is set or the agent is tainted.

This is a limited filename-component mechanism, not full path-based filesystem isolation or read/write semantic analysis.

#### Network enforcement

The controller resolves configured hostnames to IPv4 addresses when applying the policy and stores address/port entries in `egress_allow`. The BPF program checks IPv4 destinations. A configured wildcard port of zero can match any port for an allowed address.

- With `egress_default: deny`, unlisted IPv4 destinations are restricted even before taint.
- With `egress_default: allow`, unlisted destinations are allowed until the agent becomes tainted; after taint, only allow-listed destinations are accepted.
- IPv6 allow-listing is not implemented. When network access is restricted, IPv6 is treated as unlisted.
- The hooks do not inspect HTTPS request bodies, URL paths, or whether a payload contains a secret.

### 4.4 `zta_v2/bpf/kg_common.h` — shared data structures

This header defines the structures and enums shared by the kernel BPF code and user-space event reader. It defines:

- Hook identifiers: exec, file open, connect, sendmsg, BPF syscall, ptrace.
- Verdict identifiers: allow, deny, audit-deny, taint.
- Audit/enforce mode values.
- Agent configuration structure.
- Executable identity key (inode, device, agent ID).
- Network destination key (agent ID, IPv4 address, port).
- Sensitive filename key.
- Per-agent taint state.
- Ring-buffer event structure.

The byte layout must stay consistent with the packing functions in `kgctl.py` and the layout tests. Changing a shared structure requires updating all three sides.

### 4.5 BPF maps — the kernel's policy/state tables

The BPF program defines these maps:

| Map | Key → value | Purpose |
|---|---|---|
| `agent_cgroups` | cgroup ID → agent configuration | Recognises managed agent processes and their mode. |
| `exec_allow` | executable inode/device + agent ID → allowed marker | Stores permitted executable identities. |
| `sensitive_names` | filename component → taint/deny action | Stores sensitive-file rules. |
| `egress_allow` | agent ID + IPv4 + port → allowed marker | Stores allowed outbound destinations. |
| `agent_state` | cgroup ID → runtime state | Stores whether the agent has become tainted. |
| `stats` | hook/verdict counter index → count | Counts observed decisions for evaluation. |
| `events` | ring buffer | Transports event records to user space. |

Maps are the shared data path between the controller and kernel program. The controller populates policy maps; hooks perform fast lookups while the operation is being checked.

### 4.6 `zta_v2/tools/kg_events.c` — event reader

The reader opens the pinned `events` ring-buffer map using libbpf. It polls for new records and prints one JSON object per line. The record can include timestamp, cgroup ID, agent ID, hook, verdict, PID, command name, file name, inode/device, destination IP, port, and address family.

The reader is for monitoring, debugging, and collecting evidence. It does not decide whether an operation should be allowed.

### 4.7 `zta_v2/Makefile`

The Makefile builds:

- `build/kg_zta.bpf.o`: compiled eBPF object from `bpf/kg_zta.bpf.c`.
- `build/kg_events`: user-space event reader linked with libbpf.

It also provides test, optional kernel-header regeneration, and clean targets. Compilation success alone does not prove that the target kernel verifier will accept and attach the BPF program.

### 4.8 Tests and service files

- `tests/test_kgctl.py`: unit tests for controller logic, policy validation, and byte-layout consistency.
- `tests/dry_run.sh`: static checks and unit tests without loading BPF programs or changing kernel maps.
- `tests/attack_probe.py` and `tests/policy.test.yaml`: controlled probe/test inputs for later runtime validation.
- `systemd/kernelguard-zta.service`: service definition for running the controller-related service workflow.

A dry-run pass proves the checks it actually performs; it is not proof of live BPF enforcement.

## 5. End-to-end execution: from AI request to kernel decision

The following sequence combines the agent application with the v2 controller. The agent must be launched inside the managed cgroup for v2 to recognise it.

```text
Operator
  |
  | supplies GOOGLE_API_KEY to controller environment
  | selects administrator policy
  v
policy/policy.example.yaml
  |
  v
kgctl.py plan / apply
  |
  | validate YAML; resolve executable inode/device;
  | resolve configured hostname to IPv4; update BPF maps
  v
Pinned BPF maps
  |
  v
kgctl.py run research_agent -- python3 <agent-script>
  |
  | create cgroup; register cgroup ID; drop privileges;
  | pass only approved environment variables
  v
LangChain agent process
  |
  | sends task to Gemini using GOOGLE_API_KEY over HTTPS
  v
Gemini model response / tool request
  |
  v
LangChain invokes Python tool
  |
  | subprocess launches ls/cat or another configured executable
  v
Linux operation reaches BPF-LSM hook
  |
  | identify cgroup; look up relevant policy map
  v
Allow OR audit-and-allow OR enforce-and-deny
  |
  +-----------------------> BPF ring buffer
                              |
                              v
                         kg_events
                              |
                              v
                         JSON event output
```

**Where the API key and network rule meet:** the API key authenticates the agent's HTTPS request to Gemini. The v2 network hook checks the destination IP/port, not the API key or HTTPS payload. The example policy allows the Gemini API hostname on port 443 (resolved to IPv4 during `apply`) and the local DNS stub at `127.0.0.53:53`. The kernel does not inspect the encrypted request body.

## 6. Where the ML and dataset work fits

The `dataset/ml_v2/` and `model/` folders form a separate behavioural-analysis and evaluation workstream:

1. Dataset generator scripts run controlled benign or attack-like command scenarios.
2. The collectors parse the monitoring log format they are designed for and write event-level/run-level CSV data.
3. Feature extraction converts event sequences into run-level behavioural features.
4. Training/evaluation scripts compare ML models and save metrics under `results/`.

**Integration boundary:** these scripts and results do not, by themselves, prove that a trained model is called by the ZTA v2 kernel enforcement path. The current v2 kernel hooks make deterministic policy decisions from BPF maps. ML/risk analysis should be described as a separate analysis pipeline unless a tested integration is added. An LLM or ML model should not silently rewrite administrator-owned kernel policy.

Also note that attack-like dataset labels describe the scripted scenarios used by the collector. A scenario name containing `prompt_injection` does not prove a live LLM received a malicious prompt and autonomously selected the commands.

## 7. Example policy explained

The current example policy is `zta_v2/policy/policy.example.yaml`.

| Field | Meaning in the current implementation |
|---|---|
| `sensitive.taint` | Matching final filename component is allowed to open but marks the cgroup as tainted. |
| `sensitive.deny` | Matching final filename component is a violation; enforce mode rejects the open. |
| `agents.research_agent.id` | Numeric agent ID used in BPF map keys. |
| `mode` | `audit` logs violations; `enforce` rejects supported violations. |
| `run_as` | Unprivileged Linux user for the workload. |
| `workdir` | Working directory created/owned by the controller. |
| `env_passthrough` | Names of environment variables allowed into the agent environment, e.g. `GOOGLE_API_KEY`. |
| `limits.pids_max` | cgroup process-count limit. |
| `limits.memory_max` | cgroup memory limit in bytes. |
| `exec.allow` | Executables permitted by device/inode identity; optional SHA-256 can pin content. |
| `network.egress_default` | Whether unlisted IPv4 destinations are restricted by default. |
| `network.allow` | IPv4 address/port or hostname/port entries compiled into the egress map. |

The example uses `mode: audit`. It therefore records violations without blocking them. The example's `egress_default: deny` restricts unlisted IPv4 destinations even when the agent has not accessed a taint file.

## 8. Current limitations — do not overclaim

The current code should be presented with these boundaries:

1. **No prompt-text inspection:** BPF-LSM sees operating-system operations, not the natural-language prompt or model reasoning.
2. **No cryptographic model provenance:** cgroup ID identifies a managed workload, not the exact model or prompt that caused an operation.
3. **Interpreter limitation:** allowing Python permits the Python executable to start; the current executable hook does not sandbox every operation performed inside that interpreter.
4. **Filename matching limitation:** sensitive-file checks use the final filename component, not a complete path plus read/write/create/delete semantics.
5. **Network limitation:** egress allow-listing is IPv4-based; IPv6 allow-list support is not implemented.
6. **No HTTPS content inspection:** the network hook checks destination information, not encrypted request bodies or secret content.
7. **API key exposure:** an agent that receives `GOOGLE_API_KEY` can use that credential. Environment filtering does not isolate the secret from the process.
8. **ML integration boundary:** saved ML models/results are not automatically part of the synchronous BPF-LSM decision path.
9. **Research prototype status:** unit tests and dry-run checks do not prove verifier acceptance, successful attachment, or end-to-end live enforcement.

## 9. Safe development and validation sequence

Use the following staged approach in a disposable test VM:

1. Inspect the policy with `./kgctl.py plan -p policy/policy.example.yaml`.
2. Run the unit tests with `make test` or the documented dry-run script.
3. Build the BPF object and event reader with `make`.
4. Run `./kgctl.py doctor` and inspect all prerequisite results.
5. Before any load/attach action, inspect existing BPF programs, links, and pins. Confirm ownership; do not detach unrelated programs.
6. Load and apply only in a disposable VM where the KernelGuard objects are known to be yours.
7. Begin with audit mode and inspect the event stream.
8. Verify allowed and denied cases with a dedicated test policy. Only then test enforce mode.
9. Check cgroup limits and event records independently.
10. Record kernel version, policy hash, build result, verifier/attach output, test command, and observed result for reproducibility.

Do not treat `doctor`, `plan`, or a passing dry run as evidence that live enforcement has been demonstrated.

## 10. Quick explanation for a project review

- **LangChain/Gemini:** decides which registered application tool to request and produces the final natural-language response.
- **Python tools:** perform the actual file/program operations requested by the agent.
- **kgctl.py:** prepares the agent's restricted Linux execution environment and loads administrator policy into BPF maps.
- **cgroup v2:** groups the agent and its child processes under one workload identity.
- **BPF-LSM hooks:** intercept selected kernel operations and make deterministic policy decisions.
- **BPF maps:** hold the active policy and per-agent state.
- **Ring buffer + kg_events:** report kernel decisions to user space as JSON.
- **Dataset/ML pipeline:** analyses collected behaviour as a separate research/evaluation component; it is not automatically the kernel's decision-maker.

That is the complete high-level execution chain: **AI request → tool invocation → Linux operation → BPF-LSM policy check → allow/deny → event reporting.**
