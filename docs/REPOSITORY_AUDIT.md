# KernelGuard repository audit and cleanup plan

**Audit baseline:** `main` at the start of this cleanup branch.  
**Cleanup branch:** `cleanup/unified-kernelguard`.  
**Canonical implementation:** `kernelguard/`.

This is an evidence-based initial audit, not a declaration that every legacy file has already been proven unused. No historical source, dataset, model artifact or result is deleted by this change.

## 1. Branch and source-of-truth decision

The default `main` branch contains recent CI work, including a compile-only BPF and event-reader build check. The previously created `unified-kernelguard` branch has diverged from `main`: it is ahead by nine commits and behind by four commits at the audit baseline.

For this cleanup, start from `main` and keep both existing branches untouched. Do not force-push, reset or merge the divergent branch without reviewing its commits. The canonical runtime implementation is the source under `kernelguard/`; the other root-level implementations are historical or research material until individually proven otherwise.

## 2. Root-level directory classification

The following names were visible in the repository root at the time of the audit.

| Path | Initial classification | Decision |
|---|---|---|
| `.github/workflows/` | Active CI configuration | Keep; preserve the compile-only build check |
| `kernelguard/` | Canonical controller, BPF-LSM, agent, policy, tests and detection modules | Keep; active development |
| `agents/` | Earlier agent and prompt-injection experiments | Preserve unique malicious-document and agent-driven test material; compare with canonical agent before archiving |
| `daemon/` | Earlier C-based PID-registration ZTA controller | Historical; depends on the earlier eBPF skeleton and should not be used as the active controller |
| `ebpf/` | Earlier BPF monitor/ZTA source and shared headers | Historical candidate; compare hooks and unique telemetry before archiving |
| `zta_v2/` | Earlier cgroup/inode-based ZTA implementation | Duplicate snapshot of the stronger implementation copied into `kernelguard/`; proposed rename: `archive/zta_legacy/` |
| `policies/` and root `policy.yaml` | Earlier risk-classification policy format | Historical; keep as examples/history only if needed to explain the earlier prototype |
| `dataset/` | Earlier dataset and generated records | Preserve data and reproducibility artifacts; do not delete |
| `model/` | Feature extraction, training, evaluation, inference and model artifacts | Preserve research code/artifacts; canonical runtime inference wrapper is under `kernelguard/detection/` |
| `results/` | Experiment outputs and evaluation evidence | Preserve; inspect for reproducibility and publication references |
| `scripts/` | Setup, experiment and maintenance scripts | Audit each script and its referenced paths before deciding |
| `libbpf-bootstrap/` | Earlier build scaffold/submodule candidate | Canonical `kernelguard/Makefile` does not reference it; verify no legacy script or submodule workflow depends on it before removal |

## 3. Confirmed source observations

### Canonical controller and enforcement

- `kernelguard/kgctl.py` is the controller for policy validation, BPF loading, map population, cgroup registration, privilege dropping, status/events and response tiers.
- `kernelguard/bpf/kg_zta.bpf.c` is the canonical BPF-LSM enforcement source.
- `kernelguard/bpf/kg_common.h` defines the structures shared with user space.
- `kernelguard/tools/kg_events.c` reads the ring buffer and prints JSON Lines.
- `kernelguard/policy/policy.example.yaml` is the current policy schema example.
- `kernelguard/tests/` contains controller and controlled validation tests.

### Legacy ZTA snapshot

The earlier `zta_v2/kgctl.py` and `zta_v2/bpf/kg_zta.bpf.c` implement the same core design as the canonical files: cgroup v2 identity, executable allow-list by device/inode, sensitive-file taint/deny, IPv4 egress rules, BPF/ptrace restrictions and audit/enforce modes. The canonical versions have different file blob hashes, so they must not be assumed byte-for-byte identical. The canonical Makefile is independent of the legacy Makefile.

The canonical BPF source still contains an outdated comment referring to `zta_v2/Makefile`; this should be corrected to `kernelguard/Makefile`.

### Dataset and model

The canonical dataset documentation and generators still use the legacy `logs/kernelguard_live.log` text format. They are not yet consuming the canonical `kg_events` BPF JSON stream. The old `model/` tree contains the training/evaluation work that is not represented by the canonical inference wrapper alone. These files are research dependencies and must not be deleted merely because they are outside `kernelguard/`.

## 4. ZTA policy lifecycle

1. Administrator edits a YAML policy under `kernelguard/policy/`.
2. `kgctl.py plan` validates the schema and resolves executable and network entries without loading BPF.
3. `kgctl.py load` loads and attaches the BPF-LSM programs and pins maps.
4. `kgctl.py apply` writes the compiled policy into the pinned maps and records a SHA-256 of the policy file.
5. `kgctl.py run` verifies that the policy has not changed, creates a dedicated cgroup v2, registers its ID, drops the child to an unprivileged account and launches the agent.
6. BPF-LSM hooks identify the current cgroup and evaluate covered operations against the maps.
7. Audit mode records a violation but allows the operation; enforce mode returns `-EPERM` for a denied operation.
8. The event reader exports evidence. ML remains out-of-band and does not itself enforce a syscall.

The administrator is the policy authority. The AI agent must not be allowed to modify the policy file, pinned maps or controller state.

## 5. Research attack scope

The primary attack scenario is prompt injection leading to attempted restricted command execution, particularly shell or sudo invocation. The dataset also defines shell chains, password-utility help invocation, temporary executable, unknown executable, benign-to-sudo, benign-to-shell and repeated sudo/shell scenarios.

The current dataset's `prompt_injection_sudo` and `prompt_injection_bash` records are generated by scripted command sequences. They are attack-like simulations, not proof of an autonomous LLM selecting those commands after reading a malicious document. A live agent-driven experiment must capture the document, prompt, model/tool-call trace, process/cgroup identity and BPF event to support that claim.

## 6. Dataset provenance

The dataset README documents 800 benign runs and 300 attack-like runs (1,100 planned runs total), with 2,781 events in the described generated dataset. The benign collection comprises 40 simple tasks repeated 10 times and 20 composite workflows repeated 20 times. Ten attack-like workflows are repeated 30 times each.

The generators read the legacy text log format:
`PID | UID | PROCESS | PATH | RISK | REASON | ACTION`.

Use actual CSV contents and row counts as the authority if the dataset is regenerated. Do not report the documented counts as freshly reproduced results without rerunning the collectors. Do not claim the current BPF ring buffer is the source of these records.

## 7. Proposed archive/rename plan

After the full file-level dependency check and clean-checkout tests:

- Rename `zta_v2/` to `archive/zta_legacy/` so the old implementation remains accessible but is no longer presented as an active version.
- Move genuinely historical v1 source under a clearly named archive only when it has no active build/runtime references.
- Keep unique prompt-injection fixtures, data generators, training scripts, model artifacts and results in research-oriented locations.
- Remove generated caches, temporary build outputs, duplicate binaries, stale skeletons and unreferenced setup scripts only after confirming they are reproducible or unnecessary.
- Keep one active policy format under `kernelguard/policy/`.

**Rename status:** proposed, not yet executed. A folder rename requires the complete tracked file list and Git tree update; changing documentation alone is not a rename.

## 8. Required verification gates before deletion

- [ ] Enumerate every tracked file under `agents/`, `daemon/`, `ebpf/`, `dataset/`, `model/`, `policies/`, `results/`, `scripts/`, `zta_v2/` and `libbpf-bootstrap/`.
- [ ] Search all tracked scripts, service units, Makefiles, workflows and documentation for references to each candidate path.
- [ ] Compare duplicate BPF/controller files and retain unique code or experimental evidence.
- [ ] Confirm dataset CSVs, model artifacts and result files can be traced to their generators and evaluation scripts.
- [ ] Run canonical Python unit tests and dry-run policy validation from a clean checkout.
- [ ] Run CI compile-only BPF and event-reader checks.
- [ ] On the target disposable VM, record kernel version, BPF-LSM availability, BTF, verifier load, attach result, ring-buffer events, audit result and enforce result.
- [ ] Only then delete confirmed unused generated or duplicate files.

## 9. Safety and rollback

All cleanup work is on `cleanup/unified-kernelguard`, created from `main`. Existing `main` and `unified-kernelguard` are preserved. Historical source is not deleted until the above gates pass. Review the branch diff before merging.
