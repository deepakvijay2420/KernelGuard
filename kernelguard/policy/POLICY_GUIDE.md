# KernelGuard ZTA v2 policy guide

Policy file: `policy/policy.hardened.yaml`. Everything below is about what that file does, why, and
what it does **not** do. Rules marked *(kernel-tested: no)* have unit tests but have not yet been
exercised against a real BPF-LSM kernel; run `tests/bypass_suite.sh` before claiming them.

## 1. Choosing a profile

| Profile | Use when | Network | Exec set | Limits |
|---|---|---|---|---|
| `airgapped_agent` | sensitive local documents, **local** model | none (not even DNS) | 7 read-only tools | 16 tasks, 2 GiB |
| `research_agent` (default) | read text, reason, call the Gemini API | Gemini :443 + DNS | 13 read-only tools | 32 tasks, 512 MiB |
| `coding_agent` | research plus diff/cut/tr, bigger test runs | Gemini :443 + DNS | 15 tools, no shell/compiler/pkg/git | 64 tasks, 1 GiB |

Pick the smallest profile that does the job. Moving up a profile is a decision, not a default.

## 2. Rule by rule

| Rule | Attack it stops | What it does not stop |
|---|---|---|
| Exec allow-list by inode, deny by default | Injected `sudo`, `bash`, `curl`, `nc`, compilers, package managers; symlink / copy / `../` / prefix tricks (same inode or not listed) | Anything the allowed binaries can do by themselves, above all **`python3`** (see section 4) |
| `sha256` pin (via `policy_pin.py`) | A binary swapped or patched after the policy was written | A compromised package at pin time; hashes change on `apt upgrade` |
| Egress deny + exact allow-list | Exfiltration to any host except the LLM API; reverse shells | Data hidden inside the allowed API call; DNS tunnelling while the DNS line is present |
| `sensitive.taint` (65 names total with deny) | Read-secret-then-send: after the read the agent may reach only the allow-list | The read itself (it is allowed on purpose, so normal work is not broken); secrets under names not listed |
| `sensitive.deny` | Reading `shadow`, `sudoers`, host keys, `kcore`, `docker.sock`, loader/persistence files, the policy itself | Reading the same data through a differently named copy the agent could create (needs write control, section 5) |
| `limits` pids/memory | Fork bombs, memory exhaustion | CPU and disk-IO abuse (no `cpu.max` / `io.max` yet) |
| `mode: audit` first | Breaking your own agent while tuning | Nothing: audit **does not block**. A policy in audit is not a defence |
| `run_as` unprivileged, `no_new_privs` (controller) | Privilege gain through setuid binaries | Kernel exploits |
| Linter (`policy_lint.py`) | A dangerous command, relative path, agent-writable binary, open egress or any-port external rule entering the policy | Logic errors it cannot see (a legitimate tool used maliciously) |

## 3. Promotion checklist: audit -> enforce

1. `python3 kgctl.py plan -p policy/policy.hardened.yaml` (resolves hosts and binaries, no root).
2. `python3 tools/policy_lint.py policy/policy.hardened.yaml` shows no FAIL.
3. Run your **real** workload at least 20 times in `mode: audit`; read `kgctl.py events`.
4. Every `audit_deny` is either a real attack or a missing legitimate tool: add the tool, never loosen a rule.
5. Zero `audit_deny` across the last 10 runs, including one run per task type.
6. `python3 tools/policy_pin.py ... > policy/policy.pinned.yaml`, set `mode: enforce`, then
   `python3 tools/policy_lint.py --strict policy/policy.pinned.yaml` must pass (this is the CI gate).
7. `sudo tests/bypass_suite.sh` must print `RESULT: PASS` on the target kernel.
8. Keep a rollback: `kgctl.py run AGENT --mode audit -- ...` overrides the mode for one run.

## 4. Known gaps you should state in the paper

* **python3 is a general-purpose interpreter.** The exec rules cannot see `python3 -c "..."`. Containment
  rests on egress, taint, file deny and limits, not on command control. Fix: argv rules (section 5) and a
  seccomp profile for the interpreter.
* **The API key is readable by the agent** (`env_passthrough`). Egress limits where it can go, not who can read it.
  Better: a local proxy that injects the key so the agent never holds it.
* **DNS** is a covert channel while `127.0.0.53:53` is allowed. `airgapped_agent` has none.
* **Name-based sensitive matching** has no wildcards and sees only the final path component.
* **Time-of-check**: inode and hash are verified at apply/start time, not continuously.

## 5. Policy-language features still to build (each needs BPF changes, so each needs kernel tests)

| # | Feature | Why | Sketch |
|---|---|---|---|
| 1 | Write rules | persistence (`.bashrc`, cron, systemd, autostart), planting a renamed copy | deny `file_open` with write flags outside `workdir` |
| 2 | Read sandbox | the agent can read most of the filesystem today | allow reads only under `workdir` and the runtime's library paths |
| 3 | argv rules for the interpreter | close the `python3 -c` hole | check `bprm->argv` in `bprm_check_security`; allow only `python3 <workdir>/agent.py` |
| 4 | CIDR deny ranges | block `169.254.169.254` (cloud metadata) and RFC1918 explicitly | LPM trie in the egress map |
| 5 | Per-agent sensitive lists | tighter rules for the air-gapped profile | key `sensitive_names` by agent id |
| 6 | Budgets | many allowed calls add up to an attack | per-run exec count and wall-clock limit that triggers `freeze` |
| 7 | Escalation ladder | one denial vs three denials in 60 s deserve different responses | controller reads the event stream and calls `tier` |

Until 1 and 2 exist, treat `workdir` as advisory: the policy does not yet stop the agent writing elsewhere
that its Unix user can already write.
