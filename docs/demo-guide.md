# KernelGuard code-review demo guide

This guide is a reproducible checklist for the academic code review. Run the safe checks first. Use live BPF commands only in the dedicated disposable Ubuntu VM where KernelGuard is installed and where you have inspected existing BPF pins and links.

## 1. Before the review

From the repository root:

```bash
cd kernelguard
python3 --version
uname -r
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
make
```

The first three validation commands are safe checks. `make` compiles the BPF object and userspace event reader; it does not load or attach them.

Record the actual output. Do not report a test as passed unless it completed successfully on the machine used for review.

## 2. Five-minute demonstration

| Time | Action | Explain |
|---|---|---|
| 0:00–0:40 | Show project and architecture | KernelGuard is a Linux runtime security research prototype for controlled AI-agent workloads. |
| 0:40–1:20 | Run `python3 kgctl.py plan -p policy/policy.example.yaml` | Administrator policy is validated and translated to planned map entries; this is a dry run. |
| 1:20–2:00 | Show `make test` output | Unit tests validate policy handling and C/Python structure layouts. |
| 2:00–3:00 | In the prepared VM, show `sudo python3 kgctl.py status` | Show whether programs/policy are loaded and what the controller reports. |
| 3:00–4:15 | Run the prepared, known-safe agent or controlled command | Demonstrate only actions already allowed by the configured policy. |
| 4:15–5:00 | Show event output or saved validation evidence | Explain the exact hook, verdict and whether the result was audit or enforced deny. |

Do not improvise a live external Gemini request as the only demo. Network/API availability can fail independently of the local KernelGuard components. Prepare a local deterministic test as the primary demonstration.

## 3. Fifteen-minute code walkthrough

### A. README and setup (2 minutes)
Explain prerequisites, policy dry-run, tests and build. Clarify that build/test results do not by themselves prove kernel enforcement.

### B. Architecture (2 minutes)
Use [architecture.md](architecture.md). Explain the controller, cgroup identity, BPF maps, LSM hooks, ring buffer and separate ML workflow.

### C. Controller and policy (3 minutes)
Open `kernelguard/kgctl.py` and `kernelguard/policy/policy.example.yaml`. Explain:
- how a policy file is parsed and validated;
- how executable identity is converted to inode/device keys;
- how the controller creates and registers a cgroup;
- how the child is run with reduced privileges;
- how policy digest checking prevents silent policy drift.

### D. Kernel hooks and shared structures (4 minutes)
Open `kernelguard/bpf/kg_common.h` first, then `kernelguard/bpf/kg_zta.bpf.c`. Explain:
- the shared `kg_event` structure;
- the `agent_cgroups`, `exec_allow`, `sensitive_names` and `egress_allow` maps;
- `bprm_check_security`, `file_open`, `socket_connect`, `socket_sendmsg`, `bpf` and `ptrace_access_check`;
- the difference between audit mode and enforce mode;
- why the enforcement hook returns `-EPERM` for an enforced denial.

### E. Telemetry and ML research (2 minutes)
Show `kernelguard/tools/kg_events.c`, then the detection modules. State clearly that the canonical reader produces JSON Lines but the historic dataset collector uses a legacy text schema; a tested adapter is still needed. ML is advisory/offline in the current repository.

### F. Limitations and future work (2 minutes)
Discuss IPv6 coverage, encrypted HTTPS payload visibility, allowed interpreter semantics, live event-reader validation, and end-to-end prompt-injection experiments.

## 4. Safe live-operation reminder

The example policy starts in audit mode. Audit mode logs a would-be denial but lets the operation continue. Do not tell reviewers that audit mode blocked an operation.

Only demonstrate enforce mode after confirming the exact test policy, binary allow-list and target VM. Show the actual process exit status or permission error for the specific blocked action. Do not load/unload BPF programs on a shared host.

## 5. Expected questions

**Does KernelGuard detect prompt injection inside the model?**  
No. It does not inspect prompt text or model reasoning. It constrains selected operating-system operations that may result from an agent action.

**Is ML responsible for blocking syscalls?**  
No. Kernel policy is the synchronous enforcement authority. ML risk scoring is separate and advisory/offline in the current implementation.

**Why use cgroups instead of PID?**  
A cgroup identifies the managed process tree, including descendants, whereas a PID identifies one process instance.

**What happens in audit mode?**  
The hook records a would-be denial but allows the operation to continue.

**What happens in enforce mode?**  
For a covered operation that violates the policy, the hook returns `-EPERM`.

**Does the system inspect HTTPS request contents?**  
No. The current network hook evaluates destination metadata, not encrypted request bodies or URL paths.

**Are the ML results proof of real-world attack detection?**  
No. The current results use controlled, research-generated command workloads. More diverse and independent validation is required.

## 6. Review evidence checklist

- [ ] Exact environment and kernel version recorded.
- [ ] `make test` output saved.
- [ ] Safe dry-run output saved.
- [ ] Build output saved.
- [ ] BPF load/attach output saved, only if tested.
- [ ] Event-reader output checked for valid fields.
- [ ] Audit/enforce mode explicitly identified in screenshots/logs.
- [ ] No API keys, credentials, private logs or generated virtual environments committed.
