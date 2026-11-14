#!/usr/bin/env python3
"""Pure helpers for the ZTA v2 evaluation: statistics, parsing and LaTeX rendering.
No third-party dependencies (this file is also imported by the unit tests)."""
import errno as _errno
import json
import math
import random
import statistics

# ---------------------------------------------------------------- statistics
def percentile(sorted_vals, q):
    """Linear-interpolated percentile, q in [0,100], on an already sorted list."""
    if not sorted_vals:
        raise ValueError("empty sample")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * q / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(sorted_vals[lo])
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def summarize(samples):
    s = sorted(samples)
    return {
        "n": len(s),
        "mean": statistics.fmean(s),
        "median": percentile(s, 50),
        "p95": percentile(s, 95),
        "p99": percentile(s, 99),
        "stdev": statistics.stdev(s) if len(s) > 1 else 0.0,
        "min": s[0],
        "max": s[-1],
    }


def overhead_ci(base_round_medians, cond_round_medians, iters=5000, seed=42):
    """Percent overhead of the median-of-round-medians, with a 95% bootstrap CI that resamples
    whole rounds (so run-to-run drift is part of the interval).  Returns (pct, lo, hi)."""
    if not base_round_medians or not cond_round_medians:
        raise ValueError("need at least one round per condition")
    rng = random.Random(seed)

    def ratio(b, c):
        mb, mc = statistics.median(b), statistics.median(c)
        return (mc / mb - 1.0) * 100.0

    point = ratio(base_round_medians, cond_round_medians)
    draws = []
    for _ in range(iters):
        b = [rng.choice(base_round_medians) for _ in base_round_medians]
        c = [rng.choice(cond_round_medians) for _ in cond_round_medians]
        draws.append(ratio(b, c))
    draws.sort()
    return point, percentile(draws, 2.5), percentile(draws, 97.5)


# ------------------------------------------------------------------- parsing
def parse_probe_jsonl(text):
    """Probe output: one JSON object per line.  Non-JSON lines (kgctl banners) are skipped."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if {"name", "expect", "errno", "passed"} <= o.keys():
            rows.append(o)
    return rows


def errno_name(code):
    if code == 0:
        return "success"
    if code < 0:
        return f"err{code}"
    return _errno.errorcode.get(code, str(code))


def parse_events_jsonl(text):
    """kg_events output -> {(hook, verdict): count}."""
    counts = {}
    for line in text.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and "hook" in e and "verdict" in e:
            k = (e["hook"], e["verdict"])
            counts[k] = counts.get(k, 0) + 1
    return counts


def bypass_summary(rows):
    blocked = [r for r in rows if r["expect"] == "blocked"]
    allowed = [r for r in rows if r["expect"] == "allowed"]
    return {
        "attempts": len(blocked),
        "attempts_refused": sum(1 for r in blocked if r["passed"]),
        "controls": len(allowed),
        "controls_ok": sum(1 for r in allowed if r["passed"]),
        "all_passed": all(r["passed"] for r in rows) and bool(rows),
    }


# -------------------------------------------------------------------- LaTeX
_TEX = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#",
        "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}


def tex_escape(s):
    return "".join(_TEX.get(c, c) for c in str(s))


def bypass_table_tex(rows, label="tab:bypass_measured"):
    out = [r"\begin{table}[t]",
           r"\caption{Measured Bypass Matrix on the Test Kernel (Refused = Operation Failed With \texttt{EPERM})}",
           rf"\label{{{label}}}", r"\centering\scriptsize", r"\rowcolors{2}{kggray}{white}",
           r"\begin{tabular}{@{}p{3.9cm}l l c@{}}", r"\toprule",
           r"\rowcolor{kgblue} \KH{Attempt} & \KH{Expected} & \KH{Observed} & \KH{OK}\\", r"\midrule"]
    for r in rows:
        ok = r"\checkmark" if r["passed"] else r"\textbf{FAIL}"
        out.append(f"{tex_escape(r['name'])} & {tex_escape(r['expect'])} & "
                   f"{tex_escape(errno_name(r['errno']))} & {ok}\\\\")
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(out) + "\n"


def overhead_table_tex(summ, label="tab:overhead_measured"):
    """summ: {op: {condition: {'summary':..., 'overhead': (pct, lo, hi) or None}}}"""
    conds = ["unloaded", "loaded_unconfined", "audit", "enforce"]
    head = {"unloaded": "No BPF", "loaded_unconfined": "Loaded, not confined",
            "audit": "Audit", "enforce": "Enforce"}
    out = [r"\begin{table}[t]",
           r"\caption{Per-Operation Latency (Median in $\mu$s, Overhead vs.\ No BPF with 95\% CI)}",
           rf"\label{{{label}}}", r"\centering\scriptsize", r"\rowcolors{2}{kggray}{white}",
           r"\begin{tabular}{@{}l r r r r@{}}", r"\toprule",
           r"\rowcolor{kgblue} \KH{Operation} & " + " & ".join(rf"\KH{{{head[c]}}}" for c in conds) + r"\\",
           r"\midrule"]
    for op, per in summ.items():
        cells = []
        for c in conds:
            e = per.get(c)
            if not e:
                cells.append("--")
                continue
            med = e["summary"]["median"] / 1000.0
            ov = e.get("overhead")
            cells.append(f"{med:.1f}" if ov is None else f"{med:.1f} ({ov[0]:+.1f}\\%)")
        out.append(tex_escape(op) + " & " + " & ".join(cells) + r"\\")
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(out) + "\n"
