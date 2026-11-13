#!/usr/bin/env python3
"""ZTA v2 measured evaluation (run as root on the lab VM that has a BPF-LSM kernel).

    cd zta_v2 && make && sudo python3 eval/run_eval.py --out ../results/zta_v2/$(date +%Y%m%d_%H%M%S)

Steps: record environment -> bypass matrix (tests/bypass_suite.sh) -> latency benchmark in four
conditions (unloaded, loaded-but-unconfined, audit, enforce) -> render CSV/JSON/LaTeX/SUMMARY.md.
Nothing is filtered: failed attempts and failed operations are reported, not dropped."""
import argparse
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import render_results as R  # noqa: E402

KG = [sys.executable, str(ROOT / "kgctl.py")]
WORK = Path("/var/lib/kernelguard/work/bench")
BENCH_POLICY = ROOT / "tests" / "policy.bench.yaml"
SANITY = ("import subprocess,sys\n"
          "try:\n subprocess.run(['/usr/bin/ls'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);print('RAN')\n"
          "except PermissionError:\n print('REFUSED')\n"
          "except Exception as e:\n print('OTHER',type(e).__name__)\n")


def sh(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def log(msg):
    print(f"[eval] {msg}", flush=True)


def capture_env():
    def first(cmd):
        try:
            return sh(cmd).stdout.strip().splitlines()[0]
        except Exception:
            return "unknown"
    cpu = "unknown"
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    lsm = Path("/sys/kernel/security/lsm")
    return {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kernel": platform.release(),
        "active_lsms": lsm.read_text().strip() if lsm.exists() else "unknown",
        "cpu": cpu,
        "cpus": os.cpu_count(),
        "virtualization": first(["systemd-detect-virt"]),
        "clang": first(["clang", "--version"]),
        "python": platform.python_version(),
        "git_commit": first(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "git_dirty": bool(sh(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]).stdout.strip()),
    }


def ensure_user():
    if sh(["id", "kgagent"]).returncode != 0:
        subprocess.run(["useradd", "--system", "--no-create-home", "kgagent"], check=True)


def run_bypass(out):
    raw = out / "raw"
    env = dict(os.environ, KG_RESULTS_DIR=str(raw))
    log("bypass matrix: tests/bypass_suite.sh (needs a few seconds)")
    p = subprocess.run(["bash", str(ROOT / "tests" / "bypass_suite.sh")], text=True, capture_output=True,
                       env=env, cwd=ROOT)
    (raw / "bypass_suite.log").write_text(p.stdout + "\n--- stderr ---\n" + p.stderr)
    log(f"bypass suite exit status {p.returncode} (0 = every attempt refused and every control worked)")
    return p.returncode


def parse_json_line(text):
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError("workload produced no JSON; output was:\n" + text[-800:])


def run_workload(condition, iters, exec_iters):
    args = ["--iters", str(iters), "--exec-iters", str(exec_iters)]
    path = str(WORK / "workload.py")
    if condition in ("unloaded", "loaded_unconfined"):
        p = subprocess.run(["/usr/bin/python3", path, *args], text=True, capture_output=True,
                           user="kgagent", env={"PATH": "/usr/bin:/bin"})
    else:
        p = subprocess.run([*KG, "run", "bench", "--mode", condition, "--", "/usr/bin/python3", path, *args],
                           text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"workload failed in {condition}: rc={p.returncode}\n{p.stdout[-500:]}\n{p.stderr[-800:]}")
    return parse_json_line(p.stdout)


def sanity_check():
    """Enforce must refuse a non-listed exec, audit must allow it.  Otherwise timing means nothing."""
    res = {}
    for mode in ("audit", "enforce"):
        p = subprocess.run([*KG, "run", "bench", "--mode", mode, "--", "/usr/bin/python3", "-c", SANITY],
                           text=True, capture_output=True)
        res[mode] = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else f"no output rc={p.returncode} {p.stderr[-200:]}"
    ok = res.get("enforce") == "REFUSED" and res.get("audit") == "RAN"
    return ok, res


def run_overhead(out, iters, exec_iters, rounds, seed):
    ensure_user()
    WORK.mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "workload.py", WORK / "workload.py")
    os.chmod(WORK / "workload.py", 0o644)
    shutil.chown(WORK, "kgagent")
    samples, rng = [], random.Random(seed)
    pre, post = max(rounds // 2, 1), max(rounds - rounds // 2, 1)

    def one(rnd, phase, cond):
        t0 = time.time()
        r = run_workload(cond, iters, exec_iters)
        samples.append({"round": rnd, "phase": phase, "condition": cond, "ops": r["ops"], "errors": r["errors"]})
        log(f"round {rnd:>2} {phase:<4} {cond:<18} {time.time() - t0:5.1f}s  failed ops: {sum(r['errors'].values())}")

    log("phase 1/3: BPF unloaded (true baseline)")
    sh(KG + ["unload", "--force"])
    for i in range(pre):
        one(i, "pre", "unloaded")

    log("phase 2/3: load + apply bench policy, interleave the three loaded conditions")
    for cmd in (KG + ["load"], KG + ["apply", "-p", str(BENCH_POLICY)]):
        p = sh(cmd)
        if p.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)} failed:\n{p.stdout}\n{p.stderr}")
    ok, res = sanity_check()
    if not ok:
        sh(KG + ["unload", "--force"])
        raise RuntimeError(f"sanity check failed ({res}): enforcement is not behaving, refusing to benchmark")
    for i in range(rounds):
        order = ["loaded_unconfined", "audit", "enforce"]
        rng.shuffle(order)
        for cond in order:
            one(i, "main", cond)

    log("phase 3/3: unload again, repeat the baseline to measure drift")
    sh(KG + ["unload", "--force"])
    for i in range(post):
        one(i, "post", "unloaded")

    (out / "raw" / "overhead_raw.json").write_text(json.dumps({
        "meta": {"iters": iters, "exec_iters": exec_iters, "rounds": rounds, "seed": seed,
                 "baseline_rounds": pre + post, "sanity": res}, "samples": samples}))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="output directory (created)")
    ap.add_argument("--iters", type=int, default=2000, help="iterations per op per round")
    ap.add_argument("--exec-iters", type=int, default=400, help="iterations of the slow exec op per round")
    ap.add_argument("--rounds", type=int, default=15)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-bypass", action="store_true")
    ap.add_argument("--skip-overhead", action="store_true")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (loads BPF programs and creates cgroups)")
    out = Path(a.out).resolve()
    (out / "raw").mkdir(parents=True, exist_ok=True)

    d = sh(KG + ["doctor"])
    (out / "raw" / "doctor.txt").write_text(d.stdout + d.stderr)
    if d.returncode != 0:
        sys.exit("kgctl doctor says this machine cannot enforce; fix the FAIL lines first:\n" + d.stdout)
    env = capture_env()
    (out / "raw" / "env.json").write_text(json.dumps(env, indent=2))
    log(f"kernel {env['kernel']}, LSMs: {env['active_lsms']}, virtualization: {env['virtualization']}")

    rc = 0
    try:
        if not a.skip_bypass:
            rc = run_bypass(out)
        if not a.skip_overhead:
            run_overhead(out, a.iters, a.exec_iters, a.rounds, a.seed)
    finally:
        sh(KG + ["unload", "--force"])
    R.render(str(out))
    log(f"done. Read {out}/SUMMARY.md ; LaTeX tables: table_bypass.tex, table_overhead.tex")
    sys.exit(0 if rc == 0 else 1)


if __name__ == "__main__":
    main()
