# KernelGuard — Unified Code Architecture

This document describes the canonical source layout under `kernelguard/`. It combines the BPF-LSM Zero Trust enforcement core with the agent, event collection and behavioural-analysis research modules. It distinguishes implemented code from future integration work.

## 1. System overview

```text
Operator / Administrator
  |-- YAML policy
  |-- GOOGLE_API_KEY in environment
  v
KernelGuard Controller (kgctl.py)
  |-- validates policy and resolves executable/network entries
  |-- loads BPF object and populates maps
  |-- creates cgroup v2 and registers its ID
  v
LangChain + Gemini agent
  |-- model requests a registered tool
  |-- Python tool invokes subprocess/file operation
  v
Linux operation -> BPF-LSM hook
  |-- obtains current cgroup ID
  |-- looks up agent and policy maps
  |-- allow / audit-and-allow / enforce-deny
  +----------------------> BPF ring buffer -> kg_events JSONL
                                             |
                                             v
                              Behavioural analysis (separate)
                                             |
                                             v
                                  Operator response/review
```

The BPF-LSM hook is the synchronous enforcement point. The ring buffer transports events. Behavioural ML is not currently invoked synchronously by the BPF program.

## 2. Canonical layout

```text
kernelguard/
├── agent/langchain_gemini_agent.py
├── bpf/kg_zta.bpf.c
├── bpf/kg_common.h
├── tools/kg_events.c
├── tools/policy_lint.py
├── policy/
│   ├── policy.example.yaml
│   ├── policy.hardened.yaml
│   └── dangerous_commands.yaml
├── tests/
│   ├── test_kgctl.py
│   ├── dry_run.sh
│   ├── attack_probe.py
│   └── policy.test.yaml
├── detection/
│   ├── behavior_features.py
│   ├── behavior_ml.py
│   └── risk_fusion.py
├── dataset/README.md and generators/
├── systemd/kernelguard.service
├── kgctl.py
└── Makefile
```

## 3. Agent and Gemini API integration

The agent example uses LangChain's `create_agent`, `ChatGoogleGenerativeAI` and registered Python tools. The model can request a registered tool; LangChain executes it and returns the result to the model for its final response.

The example tools are deliberately narrow:
- `list_files()` runs `ls -la` against its configured lab directory.
- `read_research_file()` runs `cat` against its configured `research.txt`.

The system prompt restricts the model to these tools, but a prompt is not an operating-system security boundary. The controller's cgroup and BPF-LSM controls are the separate OS-level boundary.

### API key flow

The source constructs `ChatGoogleGenerativeAI` without a literal key. The LangChain Google integration normally obtains credentials from `GOOGLE_API_KEY` in the process environment.

1. The operator exports `GOOGLE_API_KEY` before starting the controller.
2. The policy lists the variable name under `env_passthrough`.
3. `kgctl.py run` builds a minimal child environment and copies only listed variables that exist in the controller environment.
4. The agent process receives the key.
5. The Google client reads it to authenticate HTTPS requests to Gemini.

The key is not stored as a value in YAML, compiled into BPF, or written to BPF maps. However, the agent process can access it because it receives it. This is environment filtering, not a secret vault. Never commit, print or screenshot the key.

The network hook checks destination information, not the API key or encrypted HTTPS request body. Hostnames in the policy are resolved to IPv4 addresses during `apply`; DNS changes require policy reapplication.

## 4. Controller: `kgctl.py`

| Command | Responsibility |
|---|---|
| `doctor` | Checks kernel configuration, BTF, cgroup v2, bpffs, bpftool and build artifacts. Does not prove live enforcement. |
| `plan -p POLICY` | Validates YAML and prints the map plan without loading BPF. |
| `load` | Loads the compiled BPF object, pins maps/programs and auto-attaches LSM programs. |
| `apply -p POLICY` | Compiles policy into BPF map entries and records policy SHA-256. |
| `run AGENT -- COMMAND` | Verifies policy hash, creates cgroup, registers cgroup ID, drops privileges and launches the command. |
| `tier AGENT observe|restrict|freeze|thaw|kill` | Provides operator response actions for a managed workload. |
| `status` | Displays controller state, running agents and available decision counters. |
| `events` | Starts the JSON ring-buffer event reader. |
| `unload` | Removes this controller's pinned links/programs/maps. Use only after ownership checks and stopping managed agents. |

### Agent identity and isolation

The controller creates a cgroup v2 directory and uses its inode number as the cgroup ID. It registers that ID in `agent_cgroups`. BPF code calls `bpf_get_current_cgroup_id()` and looks it up. Children inherit cgroup membership, so identity follows the workload. This identifies a managed workload; it does not cryptographically prove which model or prompt generated a command.

The controller attempts to apply `pids.max` and `memory.max`, uses an unprivileged Linux account, clears supplementary groups, sets `PR_SET_NO_NEW_PRIVS`, changes to the configured working directory and builds a minimal environment. Resource limits are cgroup controls, not BPF-LSM hooks.

## 5. BPF-LSM hooks: `bpf/kg_zta.bpf.c`

| Hook | Trigger | Current check |
|---|---|---|
| `bprm_check_security` | Executable launch | Looks up (device, inode, agent ID) in `exec_allow`; unlisted binary is a violation. |
| `file_open` | File open | Checks final resolved filename component in `sensitive_names`; taints or reports violation. |
| `socket_connect` | Socket connection | Checks IPv4 address/port against egress allow-list. |
| `socket_sendmsg` | Explicit destination send, including UDP sendto | Checks destination using the same egress function. |
| `bpf` | BPF syscall | Treats an agent's BPF syscall as a violation. |
| `ptrace_access_check` | ptrace access check | Treats an agent-initiated ptrace check as a violation. |

### Audit and enforce

- `audit`: emits `audit_deny` but returns success, so the operation continues.
- `enforce`: emits `deny` and returns `-EPERM`, rejecting the operation.

The sample policy uses audit mode. Do not describe it as actively blocking until an enforce-mode test has been run and observed.

### Taint and network

Opening a filename in `sensitive.taint` is allowed but marks the agent's cgroup as tainted. The network hook restricts an agent if it is tainted or if `egress_default: deny` is set. With `egress_default: allow`, taint activates the allow-list restriction.

The egress map is IPv4 address/port based. IPv6 allow-listing is not implemented. The hooks do not inspect HTTPS body, URL path or secret payload.

## 6. BPF maps and shared structures

`bpf/kg_common.h` defines structures shared by kernel code and the user-space reader. Their byte layouts must stay aligned with the packing functions in `kgctl.py` and the layout unit test.

| Map | Key → value | Purpose |
|---|---|---|
| `agent_cgroups` | cgroup ID → agent config | Recognises managed workloads and mode. |
| `exec_allow` | agent ID + device + inode → marker | Allowed executable identities. |
| `sensitive_names` | filename component → taint/deny | Sensitive-file policy. |
| `egress_allow` | agent ID + IPv4 + port → marker | Allowed network destinations. |
| `agent_state` | cgroup ID → taint state | Runtime taint tracking. |
| `stats` | hook/verdict index → counter | Decision counters. |
| `events` | ring buffer | Sends event records to user space. |

## 7. Event reader

`tools/kg_events.c` opens the pinned ring-buffer map, polls with libbpf and prints JSON Lines. Events include timestamp, cgroup/agent identity, hook, verdict, PID, command, filename, inode/device and network destination fields. It formats decisions; it does not make policy decisions.

## 8. Policy

The administrator-authored `policy/policy.example.yaml` defines sensitive taint/deny filename lists, agent ID and mode, unprivileged account, working directory, environment pass-through names, PID/memory limits, executable allow-list and IPv4/hostname network allow-list. Executable paths are resolved to device/inode identities. Optional SHA-256 is checked by the controller. Hostnames are resolved during apply.

## 9. Behavioural detection and risk fusion

- `detection/behavior_features.py` extracts the 23 documented run-level features from event tables.
- `detection/behavior_ml.py` loads a trained model and feature list from external joblib artifacts and returns prediction/probability/risk.
- `detection/risk_fusion.py` combines a ZTA decision and ML risk into ALLOW, DENY or REVIEW. Its own documentation says ML is advisory and does not perform kernel enforcement.

The trained joblib artifacts are not included in this canonical source copy. Inference cannot run until valid artifacts are supplied at configured paths or the code is updated to a configurable artifact location.

**Integration boundary:** these modules are not currently called by the BPF hook or controller's synchronous enforcement path. A tested event consumer, feature-window builder, model invocation and safe response integration are still needed.

## 10. Dataset evidence boundaries

The current dataset collectors parse a legacy log schema:

```text
PID=... | UID=... | PROCESS=... | PATH=... | RISK=... | REASON=... | ACTION=...
```

That is not the same as the current BPF ring-buffer JSON schema. A tested adapter/correlation pipeline is needed before claiming the dataset collector consumes canonical BPF-LSM events.

Scenario names such as `prompt_injection_sudo` label scripted command sequences. They do not establish that a live LLM was prompted and autonomously selected those commands.

## 11. Build and test

From the repository root:

```bash
cd kernelguard
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
make
python3 kgctl.py doctor
```

Dry-run checks syntax, policy structure and unit tests without loading BPF or changing maps. A successful build does not prove verifier acceptance. A successful `doctor` does not prove attachment or enforcement. Live tests belong in a disposable VM after inspecting existing BPF programs, links and pins.

## 12. Known limitations

1. Kernel hooks do not inspect prompt text or model reasoning.
2. cgroup ID identifies a managed workload, not cryptographic model provenance.
3. Allowing an interpreter does not sandbox scripts executed inside it.
4. Sensitive-file matching uses final filename component, not full path and operation semantics.
5. Egress allow-listing is IPv4-only.
6. HTTPS payloads are not inspected.
7. Environment pass-through exposes the API key to the agent process.
8. Existing ML/dataset work is not a verified live BPF event-to-ML-to-enforcement pipeline.
9. This remains a research prototype; no production security guarantee is claimed.

## 13. Integration roadmap

- [ ] Add a tested adapter from BPF JSON events to the canonical feature schema.
- [ ] Implement bounded per-agent event windows and invoke ML out of band.
- [ ] Make model artifact paths configurable and version artifacts with provenance.
- [ ] Connect risk fusion to a documented controller response API with explicit thresholds and operator audit.
- [ ] Add IPv6 egress support and stronger full-path/file-operation controls.
- [ ] Add integration tests for agent → cgroup → BPF-LSM → ring buffer → user-space event.
- [ ] Record verifier, attach, audit and enforce results on supported kernel versions.
