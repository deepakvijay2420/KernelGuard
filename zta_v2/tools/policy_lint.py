#!/usr/bin/env python3
"""KernelGuard policy linter.  Usage: policy_lint.py [--strict] [--allow-open-egress] POLICY

FAIL (exit 1):
  * an exec.allow entry is a dangerous command (by name, symlink target, or identical content)
  * an exec.allow path is not absolute
  * an allowed binary (or its directory) is writable by anyone but root: the agent could replace it
  * network egress_default is 'allow'                (unless --allow-open-egress)
  * a network allow entry opens ANY port on a non-loopback address
  * an agent has no mode, or an exec.allow list that is empty
WARN (exit 1 only with --strict):
  * an allowed binary is not pinned with sha256
  * an agent is still in audit mode (not enforcing)
  * an allowed binary does not exist on this machine (cannot be checked here)
"""
import hashlib
import os
import stat
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = os.path.join(HERE, "..", "policy", "dangerous_commands.yaml")
SEARCH = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def dangerous_index(cat):
    bad_name = {n: c for c, v in cat.items() for n in v["names"]}
    bad_hash = {}
    for d in SEARCH:
        for n in bad_name:
            p = os.path.realpath(os.path.join(d, n))
            if os.path.isfile(p):
                bad_hash.setdefault(sha(p), n)
    return bad_name, bad_hash


def writable_by_non_root(path):
    """Return a reason string if `path` could be modified by a non-root user, else ''."""
    st = os.stat(path)
    if st.st_uid != 0:
        return f"owned by uid {st.st_uid}, not root"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "group/other-writable"
    d = os.path.dirname(path)
    sd = os.stat(d)
    if sd.st_uid != 0 or sd.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"directory {d} is not root-only writable"
    return ""


def lint(pol, cat, strict=False, allow_open_egress=False):
    fails, warns = [], []
    unpinned = {}
    bad_name, bad_hash = dangerous_index(cat)
    for agent, a in (pol.get("agents") or {}).items():
        if a.get("mode") not in ("audit", "enforce"):
            fails.append(f"{agent}: mode must be 'audit' or 'enforce'")
        if a.get("mode") == "audit":
            warns.append(f"{agent}: still in audit mode (logs, does not block)")
        allow = (a.get("exec") or {}).get("allow") or []
        if not allow:
            fails.append(f"{agent}: exec.allow is empty")
        for e in allow:
            p = e if isinstance(e, str) else e.get("path", "")
            pinned = isinstance(e, dict) and bool(e.get("sha256"))
            if not os.path.isabs(p):
                fails.append(f"{agent}: exec path {p!r} is not absolute")
                continue
            real = os.path.realpath(p)
            for label, name in (("path", os.path.basename(p)), ("target", os.path.basename(real))):
                if name in bad_name:
                    fails.append(f"{agent}: {p} ({label} '{name}') is in category {bad_name[name]}")
            if not os.path.isfile(real):
                warns.append(f"{agent}: {p} does not exist on this machine, cannot check it")
                continue
            if sha(real) in bad_hash:
                fails.append(f"{agent}: {p} has the same content as dangerous '{bad_hash[sha(real)]}'")
            why = writable_by_non_root(real)
            if why:
                fails.append(f"{agent}: {real} {why} (the agent or another user could replace it)")
            if not pinned:
                unpinned.setdefault(agent, []).append(p)
        net = a.get("network") or {}
        if net.get("egress_default", "deny") == "allow" and not allow_open_egress:
            fails.append(f"{agent}: egress_default is 'allow' (use deny + an allow-list, or --allow-open-egress)")
        for n in net.get("allow") or []:
            ports = n.get("ports", [n["port"]] if "port" in n else [])
            loop = str(n.get("ip", "")).startswith("127.")
            if 0 in ports and not loop:
                fails.append(f"{agent}: network entry {n} allows ANY port on a non-loopback address")
    for agent, ps in unpinned.items():
        warns.append(f"{agent}: {len(ps)} executable(s) not pinned with sha256 (run tools/policy_pin.py)")
    if strict:
        fails += [f"(strict) {w}" for w in warns]
        warns = []
    return sorted(set(fails)), sorted(set(warns))


def main(argv):
    strict = "--strict" in argv
    open_eg = "--allow-open-egress" in argv
    files = [a for a in argv if not a.startswith("--")]
    if len(files) != 1:
        print(__doc__)
        return 2
    pol = yaml.safe_load(open(files[0]))
    cat = yaml.safe_load(open(CAT))["categories"]
    fails, warns = lint(pol, cat, strict, open_eg)
    for w in warns:
        print("WARN", w)
    for f in fails:
        print("FAIL", f)
    n = sum(len(v["names"]) for v in cat.values())
    print(f"lint: {'FAILED' if fails else 'ok'} ({len(fails)} fail, {len(warns)} warn; {n} dangerous names checked)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
