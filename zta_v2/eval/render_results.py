#!/usr/bin/env python3
"""Turn raw measurements (out_dir/raw) into CSV, JSON, LaTeX tables and SUMMARY.md.
No root and no BPF needed: run it anywhere after collection.   render_results.py OUT_DIR"""
import csv
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kg_stats as K

CONDS = ["unloaded", "loaded_unconfined", "audit", "enforce"]
OPS = ["exec_true", "file_open", "tcp_connect", "udp_sendto"]


def _read(path):
    with open(path) as f:
        return f.read()


def render_bypass(out):
    rows = []
    for p in sorted(glob.glob(os.path.join(out, "raw", "probe_*.jsonl"))):
        scenario = os.path.basename(p)[len("probe_"):-len(".jsonl")]
        for r in K.parse_probe_jsonl(_read(p)):
            rows.append({**r, "scenario": scenario})
    if not rows:
        return None
    with open(os.path.join(out, "bypass_results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "name", "expect", "errno", "errno_name", "passed"])
        for r in rows:
            w.writerow([r["scenario"], r["name"], r["expect"], r["errno"], K.errno_name(r["errno"]), r["passed"]])
    summary = K.bypass_summary(rows)
    ev_path = os.path.join(out, "raw", "kernel_events.jsonl")
    events = K.parse_events_jsonl(_read(ev_path)) if os.path.exists(ev_path) else {}
    summary["kernel_events"] = {f"{h}:{v}": n for (h, v), n in sorted(events.items())}
    with open(os.path.join(out, "bypass_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(out, "kernel_events.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["hook", "verdict", "count"])
        for (h, v), n in sorted(events.items()):
            w.writerow([h, v, n])
    with open(os.path.join(out, "table_bypass.tex"), "w") as f:
        f.write(K.bypass_table_tex(rows))
    return rows, summary


def render_overhead(out):
    p = os.path.join(out, "raw", "overhead_raw.json")
    if not os.path.exists(p):
        return None
    raw = json.loads(_read(p))
    pooled = {op: {c: [] for c in CONDS} for op in OPS}
    medians = {op: {c: [] for c in CONDS} for op in OPS}
    errors = {}
    for rec in raw["samples"]:
        c = rec["condition"]
        for op, vals in rec["ops"].items():
            if vals:
                pooled[op][c].extend(vals)
                medians[op][c].append(K.percentile(sorted(vals), 50))
        for op, n in rec.get("errors", {}).items():
            errors[(op, c)] = errors.get((op, c), 0) + n
    result, flat = {}, []
    for op in OPS:
        result[op] = {}
        for c in CONDS:
            if not pooled[op][c]:
                continue
            s = K.summarize(pooled[op][c])
            ov = None
            if c != "unloaded" and medians[op]["unloaded"]:
                ov = K.overhead_ci(medians[op]["unloaded"], medians[op][c])
            result[op][c] = {"summary": s, "overhead": ov, "rounds": len(medians[op][c])}
            flat.append([op, c, s["n"], len(medians[op][c]), round(s["median"]), round(s["mean"]),
                         round(s["p95"]), round(s["p99"]), round(s["stdev"]),
                         "" if ov is None else round(ov[0], 2), "" if ov is None else round(ov[1], 2),
                         "" if ov is None else round(ov[2], 2), errors.get((op, c), 0)])
    with open(os.path.join(out, "overhead_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["op", "condition", "n", "rounds", "median_ns", "mean_ns", "p95_ns", "p99_ns", "stdev_ns",
                    "overhead_pct", "ci95_lo_pct", "ci95_hi_pct", "failed_ops"])
        w.writerows(flat)
    with open(os.path.join(out, "overhead_summary.json"), "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.join(out, "table_overhead.tex"), "w") as f:
        f.write(K.overhead_table_tex(result))
    # drift between the baseline measured before and after the confined phases
    drift = {}
    for op in OPS:
        pre = [K.percentile(sorted(r["ops"][op]), 50) for r in raw["samples"]
               if r["condition"] == "unloaded" and r.get("phase") == "pre" and r["ops"].get(op)]
        post = [K.percentile(sorted(r["ops"][op]), 50) for r in raw["samples"]
                if r["condition"] == "unloaded" and r.get("phase") == "post" and r["ops"].get(op)]
        if pre and post:
            import statistics
            drift[op] = (statistics.median(post) / statistics.median(pre) - 1) * 100
    return result, errors, drift, raw.get("meta", {})


def write_summary(out, bypass, overhead):
    L = ["# ZTA v2 measured evaluation", ""]
    envp = os.path.join(out, "raw", "env.json")
    if os.path.exists(envp):
        env = json.loads(_read(envp))
        L += ["## Environment", ""] + [f"- **{k}**: {v}" for k, v in env.items()] + [""]
        if str(env.get("virtualization", "none")).lower() not in ("none", ""):
            L += ["> **Caveat:** measured inside a virtual machine (`%s`). Absolute latencies are noisy; "
                  "report overhead ratios with their confidence intervals, not absolute microseconds." % env["virtualization"], ""]
    if bypass:
        rows, s = bypass
        L += ["## Bypass matrix", "",
              f"- Attacks refused with EPERM: **{s['attempts_refused']} / {s['attempts']}**",
              f"- Positive controls still working: **{s['controls_ok']} / {s['controls']}**",
              f"- Overall: **{'PASS' if s['all_passed'] else 'FAIL'}**", ""]
        fails = [r for r in rows if not r["passed"]]
        if fails:
            L += ["### Failures (report these in the paper)", ""]
            L += [f"- `{r['scenario']}` / {r['name']}: expected {r['expect']}, got {K.errno_name(r['errno'])}" for r in fails] + [""]
        if s["kernel_events"]:
            L += ["Kernel-side decision events seen: " + ", ".join(f"`{k}`={v}" for k, v in s["kernel_events"].items()), ""]
    if overhead:
        result, errors, drift, meta = overhead
        L += ["## Latency overhead", "",
              f"Rounds per condition and iterations per op are in `raw/overhead_raw.json` meta: {meta}", "",
              "| operation | condition | median (us) | p99 (us) | overhead vs unloaded (95% CI) |", "|---|---|---:|---:|---:|"]
        for op, per in result.items():
            for c, e in per.items():
                ov = e["overhead"]
                ovs = "baseline" if ov is None else f"{ov[0]:+.1f}% [{ov[1]:+.1f}, {ov[2]:+.1f}]"
                L.append(f"| {op} | {c} | {e['summary']['median']/1000:.1f} | {e['summary']['p99']/1000:.1f} | {ovs} |")
        L.append("")
        if drift:
            L += ["Baseline drift (post vs pre, median): " + ", ".join(f"{o} {d:+.1f}%" for o, d in drift.items()) +
                  ". If this is larger than the overhead being claimed, repeat the run on a quieter machine.", ""]
        if errors:
            L += ["> **Failed operations were excluded from timing:** " + ", ".join(f"{o}/{c}: {n}" for (o, c), n in errors.items()), ""]
    with open(os.path.join(out, "SUMMARY.md"), "w") as f:
        f.write("\n".join(L) + "\n")


def render(out):
    b = render_bypass(out)
    o = render_overhead(out)
    write_summary(out, b, o)
    return b, o


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: render_results.py OUT_DIR")
    render(sys.argv[1])
    print("rendered into", sys.argv[1])
