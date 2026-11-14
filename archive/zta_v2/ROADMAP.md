# KernelGuard — Route Map to a Strong Policy and a Real Zero Trust Layer

This file has three parts.

1. **What you now have** (the `zta_v2/` module) and exactly what has and has not been tested
2. **The route map** — 8 phases, each with *why*, *how*, and *done when*
3. **Reference** — wording changes for the README/paper, the evaluation plan, known limits

---

## Part 1 — What is in `zta_v2/`

| File | Purpose |
|---|---|
| `bpf/kg_zta.bpf.c` | Kernel enforcement: 6 BPF-LSM programs (exec, file_open, socket_connect, socket_sendmsg, bpf, ptrace_access_check) |
| `bpf/kg_common.h` | Structs shared by kernel code, the events reader and Python |
| `kgctl.py` | One controller: `doctor`, `plan`, `load`, `apply`, `run`, `tier`, `status`, `events`, `unload` |
| `tools/kg_events.c` | Streams every decision as JSON lines (your labelled ground truth) |
| `policy/policy.example.yaml` | Deny-by-default policy for your `research_agent` |
| `tests/test_kgctl.py` | 30 unit tests (no root needed) |
| `tests/attack_probe.py`, `tests/bypass_suite.sh`, `tests/policy.test.yaml` | 19 checks (15 bypass attempts + 4 positive controls) that run *inside* a confined agent |
| `Makefile`, `systemd/kernelguard-zta.service` | Build and boot-time loading |

### What changed versus v1 and why it matters

| Weakness in v1 (`ebpf/zta/`) | v2 fix |
|---|---|
| Identity = one PID + 8-level parent walk. Double-fork, reparenting to init, PID reuse all escape it | Identity = **cgroup v2 id** created by the controller. Children inherit it. The agent (unprivileged, no_new_privs) cannot move itself out |
| Executable matched by hard-coded 64-byte path prefix (`/usr/bin/sudoedit` matched `sudo`; symlinks, `../`, copies bypass) | Executable matched by **(device, inode)** from the kernel's `bprm->file`. Strings never enter the decision |
| Deny-list of 4 binaries; everything else runs | **Deny by default**: only inodes in `exec_allow` run |
| Exec hook only | + `file_open` (sensitive names), `socket_connect` + `socket_sendmsg` (egress), `bpf`, `ptrace` |
| No state | **Taint**: read a secret → egress is cut to the allow-list only (stateful, context-aware policy) |
| Rules hard-coded in C | YAML policy compiled into maps; validated; hashed at `apply`; `run` refuses if it changed |
| Kill the controller → protection vanishes silently | Programs + links pinned in bpffs; `unload` refuses while agents run |
| No way to test a policy safely | per-agent `audit` / `enforce`; audit logs `audit_deny` without blocking |
| Binary or ML decision → only "REVIEW" | `kgctl.py tier`: restrict → freeze → kill (cgroup.freeze / cgroup.kill) |

### Verified vs NOT verified — read this

Verified here (sandbox without BPF-LSM):
- `make` builds `kg_zta.bpf.o` (clang, **no undefined symbols**, all 6 LSM sections present) and `kg_events`
- 30 unit tests pass, including a test that compiles `kg_common.h` with gcc and checks every struct size against the Python `struct.pack` layouts
- `kgctl.py plan` validates/rejects policies; `doctor` correctly reports an unsuitable machine

**Not verified (no BPF-LSM kernel or bpftool in this sandbox):** loading into the kernel and passing the BPF verifier, the real enforcement behaviour, `kgctl.py run`, cgroup handling, and the bypass suite. They are written to be run on *your* Ubuntu 22.04 / kernel 6.8 machine. Expect to fix a few small things (verifier complaints, a `bpftool` flag, a path) in your first session — Phase 2 budgets time for that. Treat the bypass suite as the acceptance test for the code, not as evidence that it passes.

### Quick start (your Ubuntu machine, as root where shown)

```bash
cd ~/kernelguard/zta_v2
sudo apt install -y clang libbpf-dev linux-tools-common linux-tools-$(uname -r) python3-yaml
make && make test                          # builds + 30 unit tests
sudo useradd --system --no-create-home kgagent
sudo ./kgctl.py doctor                     # every line must be OK (fix FAIL lines first)
sudo ./kgctl.py load                       # loads + attaches 6 LSM programs
sudo ./kgctl.py apply -p policy/policy.example.yaml
sudo ./kgctl.py events &                   # JSON stream of decisions
sudo ./kgctl.py run research_agent -- /usr/bin/python3 /opt/kernelguard/agents/agent.py
sudo ./kgctl.py status
sudo tests/bypass_suite.sh                 # acceptance test (stop other agents first)
```

Your current agent lives under `/home/deepak/...`. Ubuntu 22.04 homes are `750`, so the unprivileged `kgagent` user cannot read them. Copy the agent to a world-readable place:

```bash
sudo install -d -m 0755 /opt/kernelguard/agents
sudo python3 -m venv /opt/kernelguard/agent-venv
sudo /opt/kernelguard/agent-venv/bin/pip install langchain langchain-google-genai
sudo install -m 0644 ~/kernelguard/agents/langchain_agent/kernelguard_identity_agent_v2.py /opt/kernelguard/agents/agent.py
sudo ./kgctl.py run research_agent -- /opt/kernelguard/agent-venv/bin/python /opt/kernelguard/agents/agent.py
```

(`/opt/.../python` is a symlink; the controller resolves it to the real `python3.10` inode, which is what the policy lists as `/usr/bin/python3`.)

---

## Part 2 — The Route Map

Order matters: each phase unlocks the next. Effort assumes one person, in working days.

```
P0 truth  ->  P1 hygiene  ->  P2 audit  ->  P3 enforce  ->  P4 lifecycle
 0.5d          1d             2-3d          2-3d            2d
                                              |
                                              v
                              P5 ML->tiers -> P6 coverage -> P7 evaluation + paper
                               4-5d           5-8d           5-7d
```

### Phase 0 — Establish ground truth about your machine (0.5 day)

**Why:** every later claim depends on the kernel really enforcing.

**How**
1. `sudo ./kgctl.py doctor`. You must see OK for: kernel ≥ 5.15, `bpf` in the LSM list, BTF, cgroup v2, bpftool, bpffs.
2. If `bpf` is not listed: add `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to `GRUB_CMDLINE_LINUX`, `sudo update-grub`, reboot. (Your prototype already loads BPF-LSM programs, so this is probably done.)
3. Run **all experiments in a VM snapshot**, never on your daily machine. Adversarial prompts + root-run controller = real risk.

**Done when:** `doctor` shows no FAIL.

### Phase 1 — Repository hygiene so results are reproducible (1 day)

**Why:** reviewers (and you in three months) must be able to rebuild what produced a number.

**How**
1. Keep v1 as `legacy/` (move `ebpf/zta`, `daemon/zta`); it documents your first result honestly.
2. **One** agent file (`agents/langchain_agent/agent.py`) and **one** runner. Today five near-duplicate `kernelguard_*agent*.py` files exist and two run scripts regenerate agent source from heredocs, so the committed `.py` may not be what ran.
3. Remove the 21 hard-coded `/home/deepak` paths: use `KG_*` env vars (see top of `kgctl.py`) or `/etc/kernelguard`, `/opt/kernelguard`.
4. `libbpf-bootstrap` is a gitlink without `.gitmodules`: either `git submodule add https://github.com/libbpf/libbpf-bootstrap` or delete it (zta_v2 only needs `libbpf-dev`).
5. Stop committing generated `*.skel.h`. v2 does not use skeletons at all.
6. Remove `bpf_printk` from hot paths (v2 already uses the ring buffer).
7. In the reader (`ebpf/kernelguard_reader.c`): it `popen()`s `python3` for **every** exec event (≈3.7 ms) and **ignores** `/bin/sh` and `python3` events to avoid self-triggering. An attacker's shell or python run is therefore never logged. Replace it with `kg_events` (JSON lines) and do analysis in-process in Python.

**Done when:** a fresh `git clone` + the Quick start reproduces everything; no `/home/deepak` string remains (`grep -rn /home/deepak`).

### Phase 2 — Run ZTA v2 in AUDIT mode on your real agent (2–3 days)

**Why:** you cannot write a strong policy without seeing what the agent legitimately does. Audit mode logs every would-be denial without breaking the run.

**How**
1. Keep `mode: audit` in `policy.example.yaml`. Start `kgctl.py events > audit.jsonl`.
2. Run your normal benign workload 30+ times (your 20 task categories).
3. Analyse: every `audit_deny` is either a missing allow-list entry (add it) or something the agent should never do (leave it, it is your first real finding).
4. **Expect these first-run problems:**
   - *Google API IPs rotate.* `apply` pins the IPs resolved *at that moment*; the Gemini endpoint returns many. Run a refresh timer (`systemd` timer calling `kgctl.py apply` every 10–15 min) now, and add CIDR support (Phase 6) before you rely on it. Audit mode will show you the denied IPs.
   - *IPv6.* Python may try an AAAA address first; v2 treats IPv6 as unlisted (denied when restricted) and the client falls back to IPv4. If your client does not fall back, set the resolver to prefer IPv4.
   - *Verifier errors on first load.* If `load` fails, run the failing program under `bpftool -d prog load` to read the verifier log; typical fixes are bounds checks on the `name` copies. Send me the log and I will patch it.
5. Write your first real result: **"N benign tasks × M runs → X would-be denials, all explained by Y"**.

**Done when:** a benign workload produces **zero** `audit_deny` events for 30 consecutive runs.

### Phase 3 — Switch to ENFORCE and pass the bypass suite (2–3 days)

**Why:** this is the claim the whole project rests on: *deny-by-default at the kernel boundary survives a manipulated agent.*

**How**
1. Set `mode: enforce`. Re-run the benign workload: it must still complete (utility).
2. `sudo tests/bypass_suite.sh`. It runs 19 checks (15 bypass attempts + 4 controls), e.g. exec `/bin/sh`, symlink to sh, `../` traversal, copy of an allowed binary, **memfd fileless exec**, opening `shadow` via an innocent symlink name, TCP/UDP-sendto/IPv6 to non-listed hosts, ptrace, `bpf()`, cgroup escape — plus **controls** (allowed things must still work, otherwise "blocked" is meaningless).
3. Each failure is a finding: fix the BPF code or the policy, add a regression test to `attack_probe.py`.
4. Re-run your original prompt-injection demo through `kgctl.py run`. Record the kernel event, the `EPERM` the agent sees, and (important for the paper) that the agent's *prompt-level* "never use sudo" instruction was the thing that failed and the kernel was what held.

**Done when:** `RESULT: PASS` from the suite, benign utility unchanged, and you have a table: attempt → expected → observed → event emitted.

### Phase 4 — Policy lifecycle and integrity (2 days)

**Why:** a policy the agent (or any user) can edit is not authorization. Today `policy.yaml` is in the agent's home.

**How**
1. Move the policy to `/etc/kernelguard/policy.yaml`, `root:root`, mode `0600` (service file shows the commands).
2. Detached signature: `openssl dgst -sha256 -sign key.pem -out policy.sig policy.yaml`; have `apply` verify against a public key stored under `/etc/kernelguard/`. Refuse to apply unsigned/changed policy.
3. Binary integrity: pin hashes in `exec.allow` (`{path, sha256}` is already supported). This is checked at `apply` and `run`. Note it is a *time-of-check* guarantee; the strong version is **fs-verity** or **IMA appraisal** on the allow-listed binaries (state this as future work if you do not implement it).
4. Add a systemd timer for DNS refresh and `status` health.
5. Log every `apply` with the policy hash (`journalctl`), so each experiment result can cite the exact policy version.
6. Zero-trust bookkeeping: map your components to NIST SP 800-207 — `kgctl.py` + policy = Policy Administrator, the BPF maps = Policy Engine data, the six LSM programs = Policy Enforcement Points. One table in the paper is enough.

**Done when:** editing the policy without re-applying makes `run` fail closed (already implemented), and an unsigned policy is rejected.

### Phase 5 — Connect ML to graduated response; fix the ML story (4–5 days)

**Why:** right now ML and the kernel never talk: fusion outputs `REVIEW`, which means "log it". And the ML evaluation has issues (below).

**How: the bridge (new file `model/zta_bridge.py`)**
```python
import sys
sys.path.insert(0, "/opt/kernelguard/zta_v2")   # or your repo path
import kgctl
from risk_fusion import fuse_risk

# fused decision -> graduated tier
TIER = {"ALLOW": "observe", "REVIEW": "restrict", "DENY": "freeze"}

def act(agent: str, zta_decision: str, ml_risk: str) -> str:
    r = fuse_risk(zta_decision, ml_risk)
    tier = TIER[r.final_decision]
    if r.final_decision == "REVIEW" and ml_risk == "HIGH":
        tier = "freeze"                 # human gets a paused agent to inspect
    return kgctl.escalate(agent, tier)  # needs root; run the bridge as a root service
```
`restrict` = force enforce + cut egress; `freeze` = suspend all agent processes (reversible with `thaw`); `kill` = `cgroup.kill`. This turns "REVIEW" into a real containment action and gives the paper its *tiered response* result.

**How: fix the ML**
1. **Make the headline the strict experiment.** `results/ml_v2` reports 100% accuracy for all models: that is leakage (features derived from the label/policy). The strict run (0.95 accuracy, recall 0.83) is the honest one. Keep the 100% result only as a "why leakage matters" paragraph.
2. **Look at the failures you already have.** Random Forest detects 0/30 of `repeated_sudo`, `benign_to_sudo`, `benign_to_shell`, and flags 101/800 (12.6%) benign runs. Report these. Then explain: with deny-by-default exec, sudo and shells are *already blocked*, so the ML is only needed for what the allow-list cannot express (see 4).
3. **Generalization test:** leave-one-attack-category-out cross-validation. Training on `prompt_injection_sudo` and testing on `tmp_executable` is the only honest measure of "detects unseen attacks".
4. **Give ML the job only it can do.** Behaviour inside the allowed set: an allowed `python3` + allowed `cat` used in an unusual *sequence or rate* (mass file reads, rapid enumeration). Extend features with the v2 event stream: counts of `file_open` taints, `connect` attempts per window, distinct destinations.
5. **Make it online.** `behavior_ml.py` needs whole-run aggregates, so it can only judge a run *after* it ends and cannot stop the first bad exec. Compute the 23 features over a sliding window (last N events or last T seconds) and call `act()` when a window crosses the threshold. Report **time-to-detect**.
6. Calibrate thresholds for a fixed benign FPR (e.g. ≤1%), report recall at that FPR and the ROC.

**Done when:** a scripted attack that stays *inside* the allow-list (e.g. 500 rapid `cat` reads of a document directory) is caught by ML within a window and the agent is frozen — demonstrated end to end.

### Phase 6 — Close coverage gaps (5–8 days; pick by your threat model)

Do these in this order of value:

| # | Gap | Design |
|---|---|---|
| 6.1 | **CIDR / many IPs** (Google, CDNs) | `BPF_MAP_TYPE_LPM_TRIE`, key `{prefixlen, agent_id, addr}`. Trade-off: the port cannot be matched in the same trie; keep a second exact `(ip,port)` map for strict rules. Pull ranges from the provider's published JSON |
| 6.2 | **Write protection for persistence** (cron, `.bashrc`, `authorized_keys`, systemd units) | Hooks `inode_create`, `path_unlink`/`path_rename`, `file_open` with write flags; deny-by-name + deny-by-directory-inode sets generated by the controller (`/etc/cron*`, `~/.ssh`, `/etc/systemd`). This maps to your *persistence* attack class, currently invisible |
| 6.3 | **Directory sandbox for reads** (agent may read only its workspace) | Inode-set allow-list built by the controller (walk the workspace), or `bpf_d_path` prefix check where the verifier allows it on your kernel. Needed to block exfiltration of *non-sensitive-named* files |
| 6.4 | **Exfil through an allowed channel** (the agent has a legitimate HTTPS path to the Gemini API) | This cannot be fixed by IP allow-lists. Mitigations: workspace read sandbox (6.3), rate/volume counters per destination in a map, ML feature on bytes sent, or an egress proxy that inspects. State it as a limitation if not built |
| 6.5 | **IPv6 allow-list** | Second map keyed by 128-bit addr; read `sockaddr_in6` |
| 6.6 | **AF_UNIX** | Today allowed. A local daemon socket (`/var/run/docker.sock`) is a privilege-escalation route. Hook `unix_stream_connect` and allow-list socket inodes |
| 6.7 | **Fork/exec rate** | `task_alloc` counter per cgroup; the `pids.max` cgroup limit already stops fork bombs, so this is for detection signal only |
| 6.8 | **Multi-agent identity** | Sub-agents get their own cgroup *under* the parent's, with a strictly narrower allow-list (attenuation: child ⊆ parent). Matches the AARM / confused-deputy threat in your paper |
| 6.9 | **Domain-level egress** | Run a local DNS forwarder that only resolves allow-listed domains and feeds resolved IPs into `egress_allow` with TTL (this also solves 6.1 without CIDR) |

### Phase 7 — Evaluation and paper (5–7 days)

See Part 3 §2 for the experiment matrix. Do not start before Phase 3 passes — everything is measured against a working enforcer.

---

## Part 3 — Reference

### 1. Wording to change now (README / report / paper)

| Current claim | Problem | Replace with |
|---|---|---|
| "End-to-end privileged-operation blocking ✓" and "ZTA enforcement prototype ✓" | Your own `MODEL_REVIEW.md` says kernel EPERM enforcement is *future work* and `SUMMARY.md` says DENY is the policy layer, not EPERM | "Exec of four named binaries by a PID-registered agent was denied at BPF-LSM level in a demo (v1). v2 generalizes this to deny-by-default exec, file and network control [after Phase 3: evaluated with N attacks]." |
| "Agent identity" | It is a PID | "Agent identity is a cgroup v2 id created by the controller." (after v2) |
| Research paper: "DARPA OpTC provides Linux syscall traces" | OpTC is Windows host telemetry; TC E3 Cadets is FreeBSD | Use ADFA-LD / LID-DS / DongTing / TC E3 Theia-Trace for Linux, or drop external data and say "benign vs attack agent traces generated in the lab" |
| Paper: "Tetragon and Falco stop short of enforcement" | Tetragon supports Sigkill/Override actions; Falco is detection-only | "Tetragon can enforce, but its policies are static and identify workloads by container/namespace, not by agent task identity" and add Tetragon enforcement as a **baseline** |
| Paper: eBPF-PATROL "2024" | arXiv ID 2511 = Nov 2025 | Fix the year |
| Paper: injection ranked #1 by "OWASP" in §1 and "NIST" in §3.2.4 | Inconsistent | Pick one source and cite it |
| ATLAS IDs in the attack table | Several look mismatched (e.g. AML.T0054 is jailbreak, not shell escape) | Verify each on atlas.mitre.org; map persistence/lateral movement/privesc to ATT&CK IDs |
| "sub-3% overhead", "sub-microsecond", "high detection accuracy" | Stated before measurement | Remove from abstract until Phase 7 produces the numbers |

### 2. Evaluation plan (the experiments that make this publishable)

**Principle:** measure *attacker objectives achieved*, not just "detections". An attack succeeds if the secret reaches the lab listener, the privileged command runs, or the persistence file exists.

**Setup:** a VM snapshot; a local "attacker" listener inside an isolated network namespace; **dummy** secrets only; the same real LangChain/Gemini agent with a malicious document. Never use real attacker domains.

| Exp | Question | Configs compared | Metric |
|---|---|---|---|
| E1 Containment | Does it stop the attacks? | C0 none · C1 prompt-only ("never use sudo") · C2 v1 ZTA · C3 v2 audit · C4 v2 enforce · C5 v2 + ML tiers · C6 seccomp/AppArmor baseline · C7 Tetragon enforcement policy | Attack success rate per attack class, n ≥ 30 runs per cell, Wilson 95% CI |
| E2 Utility | Does it break normal work? | C0 vs C4 vs C5 | Task completion rate; false-denial rate (target ≈ 0 after Phase 2) |
| E3 Overhead | What does it cost? | C0 vs C4 | `exec` latency (1000 runs), `open()` loop, `connect()` latency, macro agent wall time, CPU. Per-hook cost: `sysctl -w kernel.bpf_stats_enabled=1; bpftool prog show` → `run_time_ns / run_cnt` |
| E4 Bypass | Can an adversary route around it? | C4 | `bypass_suite.sh` table + any new tricks you add |
| E5 ML | Does ML add value beyond rules? | rules-only vs ML-only vs both; leave-one-attack-out | Recall at fixed FPR ≤ 1%, ROC, time-to-detect, **in-allow-list attacks only** (the ones rules cannot see) |
| E6 Ablation | Which component matters? | remove cgroup identity / inode matching / taint / ML one at a time | Attack success rate change |

**Attack set (suggested 12):** direct sudo; bash via `python -c`; reverse shell to listener; read `.env` + POST to listener; read ssh key; cron persistence; `authorized_keys` write; fork bomb; local network scan; copied-binary exec; memfd exec; exfil of a *non-sensitive-named* file via the allowed API channel (the hard one, E1 will honestly show it as a gap until 6.3/6.4).

### 3. Known limits of v2 (put these in your Limitations section)

1. **Interpreters are powerful.** Allowing `python3` allows arbitrary in-process code. v2 controls what that process can *exec*, *open by sensitive name* and *connect to*, but it can still read any file that is not name-listed (fixed by 6.3) and send data to an allowed destination (6.4).
2. **Binary identity is inode-based.** If an allowed binary is modified in place (same inode), it stays allowed. Pin hashes (done at apply/run) and use fs-verity/IMA for a real guarantee.
3. **Sensitive-name matching is by final path component.** A secret in a file with an innocent name is not tainted. Extend with directory sets (6.3).
4. **DNS and rotating IPs** make host-based allow-lists brittle (6.1, 6.9).
5. **IPv6 and AF_UNIX** are not allow-listed yet (6.5, 6.6).
6. **The controller is root and trusted.** Compromise of root is out of scope; say so.
7. **Dataset/model scope.** Small, scripted, single-host data does not prove generalization.
8. **Verified only up to the unit-test level in this delivery:** the kernel-side behaviour must be confirmed by `bypass_suite.sh` on your machine.

### 4. Command cheat-sheet

| Task | Command |
|---|---|
| Check machine | `sudo ./kgctl.py doctor` |
| Validate policy offline | `./kgctl.py plan -p policy/policy.example.yaml` |
| Load / unload | `sudo ./kgctl.py load` / `sudo ./kgctl.py unload [--force]` |
| Apply policy | `sudo ./kgctl.py apply -p /etc/kernelguard/policy.yaml` |
| Run confined | `sudo ./kgctl.py run research_agent -- CMD ARGS` |
| Override mode for one run | `sudo ./kgctl.py run research_agent --mode audit -- CMD` |
| Watch decisions | `sudo ./kgctl.py events \| jq -c .` |
| Counters | `sudo ./kgctl.py status` |
| Contain a running agent | `sudo ./kgctl.py tier research_agent restrict\|freeze\|thaw\|kill` |
| Per-hook cost | `sudo sysctl -w kernel.bpf_stats_enabled=1; sudo bpftool prog show` |
| Unit tests | `make test` |
| Acceptance test | `sudo tests/bypass_suite.sh` |

### 5. Suggested weekly plan

| Week | Do | Evidence you can show |
|---|---|---|
| 1 | P0, P1, P2 | Clean repo; audit log of benign runs; first "0 false denials" statement |
| 2 | P3, P4 | Bypass-suite PASS table; before/after of the prompt-injection demo; signed policy |
| 3 | P5 | Tiered response demo; honest ML table (leave-one-attack-out) |
| 4 | P6.1–6.3 (+ any you need) | Persistence and read-sandbox attacks now blocked |
| 5 | P7 | E1–E6 results, rewritten claims, limitations section |
