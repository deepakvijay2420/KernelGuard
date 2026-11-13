# Reproducing the ZTA v2 evaluation

Needs a lab VM with a BPF-LSM kernel (`bpf` in `/sys/kernel/security/lsm`), root, clang, libbpf, bpftool.

```bash
git clone https://github.com/deepakvijay2420/KernelGuard && cd KernelGuard/zta_v2
make                                              # builds build/kg_zta.bpf.o and build/kg_events
python3 -m pytest -q tests                        # 41 unit tests, no root needed
python3 tools/policy_lint.py policy/policy.hardened.yaml
sudo python3 eval/run_eval.py --out ../results/zta_v2/$(date +%Y%m%d_%H%M%S)
```

`run_eval.py` runs `kgctl.py doctor` first and refuses to continue if the machine cannot enforce.
It then (1) records the environment, (2) runs the bypass matrix (`tests/bypass_suite.sh`),
(3) benchmarks exec / file open / TCP connect / UDP sendto in four conditions and
(4) renders everything. Default cost: about 15 rounds x 4 conditions, a few minutes.

| Output (in `--out`) | Use |
|---|---|
| `SUMMARY.md` | read this first; failures are listed, never dropped |
| `table_bypass.tex`, `table_overhead.tex` | copy next to `main.tex`; the paper `\input`s them if present |
| `bypass_results.csv`, `kernel_events.csv`, `overhead_summary.csv` | tables for the appendix |
| `raw/` | every sample, the probe logs, `env.json`, `doctor.txt` (publish these with the paper) |

## Method

- **Conditions:** `unloaded` (no BPF), `loaded_unconfined` (programs attached, process is not an agent: the fast path),
  `audit`, `enforce`. The unloaded baseline is measured before and after; the drift between the two is reported.
- **Rounds** are interleaved in random order (seeded) so slow drift does not favour one condition.
- **Overhead** = median of per-round medians vs the unloaded baseline, with a 95% bootstrap CI that resamples
  whole rounds. A CI that includes 0 means "no measurable overhead", not "zero overhead".
- A **sanity gate** checks that `enforce` really refuses a non-listed exec and `audit` allows it before any timing.
- Failed operations are counted and excluded from timing, never silently timed.
- Inside a VM (VirtualBox) absolute latencies are noisy: quote the ratios and CIs, and say it is a VM.

## What you may and may not claim

Only claim what `SUMMARY.md` shows. A kernel `EPERM` result is evidence of LSM enforcement; an `EACCES` is not
(it is ordinary file permission), which is why such cases are excluded from the matrix.
