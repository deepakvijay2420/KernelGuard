#!/usr/bin/env python3
"""Fail if any agent's exec.allow contains something from dangerous_commands.yaml,
by name, by symlink target, or by content hash (a renamed copy).  Usage: policy_lint.py POLICY"""
import hashlib, os, sys
import yaml

CAT = os.path.join(os.path.dirname(__file__), "..", "policy", "dangerous_commands.yaml")
SEARCH = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main(path):
    pol = yaml.safe_load(open(path))
    cat = yaml.safe_load(open(CAT))["categories"]
    bad_name = {n: c for c, v in cat.items() for n in v["names"]}
    bad_hash = {}
    for d in SEARCH:
        for n in bad_name:
            p = os.path.realpath(os.path.join(d, n))
            if os.path.isfile(p):
                bad_hash.setdefault(sha(p), n)
    problems = []
    for agent, a in pol["agents"].items():
        for e in a["exec"]["allow"]:
            p = e if isinstance(e, str) else e["path"]
            real = os.path.realpath(p)
            for label, name in (("path", os.path.basename(p)), ("target", os.path.basename(real))):
                if name in bad_name:
                    problems.append(f"{agent}: {p} ({label} '{name}') is in category {bad_name[name]}")
            if os.path.isfile(real) and sha(real) in bad_hash:
                problems.append(f"{agent}: {p} has the same content as dangerous '{bad_hash[sha(real)]}'")
    for p in sorted(set(problems)):
        print("FAIL", p)
    print("lint:", "FAILED" if problems else "ok", f"({sum(len(v['names']) for v in cat.values())} dangerous names checked)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
