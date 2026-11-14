#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
KernelGuard unified controller (kgctl.py)

One controller for policy, agent isolation, enforcement lifecycle and event reporting:

    kgctl.py doctor                      check the machine can run BPF-LSM
    kgctl.py plan   -p policy.yaml       validate policy, show what would be loaded (no root)
    kgctl.py load                        load + attach the BPF-LSM programs
    kgctl.py apply  -p policy.yaml       compile the policy into the BPF maps
    kgctl.py run    AGENT -- CMD ARGS    start CMD as AGENT inside its own cgroup
    kgctl.py tier   AGENT restrict|freeze|thaw|kill   tiered response
    kgctl.py status                      loaded programs, applied rules, running agents, counters
    kgctl.py events                      stream JSON decisions from the ring buffer
    kgctl.py unload                      detach everything

Design rules (Zero Trust):
  * The agent identity is the CGROUP the controller created, never a PID.
  * Executables are identified by (device, inode), never by path string.
  * Deny by default: anything not in the policy is refused (or logged in audit mode).
  * The policy file is hashed at `apply`; `run` refuses to start if it changed
    since (fail closed, no silent policy drift).
  * The agent gets a minimal environment, no new privileges, an unprivileged uid.

Needs: root, kernel >= 5.15 with CONFIG_BPF_LSM=y and "bpf" in lsm=, cgroup v2, bpftool.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
import pwd
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

# --------------------------------------------------------------------------
# Paths (overridable with environment variables, useful for tests)
# --------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
BPFFS_ROOT = Path(os.environ.get("KG_BPFFS", "/sys/fs/bpf/kg_zta"))
MAPS_DIR = BPFFS_ROOT / "maps"
PROGS_DIR = BPFFS_ROOT / "progs"
STATE_DIR = Path(os.environ.get("KG_STATE_DIR", "/var/lib/kernelguard"))
STATE_FILE = STATE_DIR / "zta_state.json"
CGROUP_ROOT = Path(os.environ.get("KG_CGROUP_ROOT", "/sys/fs/cgroup"))
KG_CGROUP = CGROUP_ROOT / "kernelguard"
BPF_OBJ = Path(os.environ.get("KG_BPF_OBJ", HERE / "build" / "kg_zta.bpf.o"))
EVENTS_BIN = Path(os.environ.get("KG_EVENTS_BIN", HERE / "build" / "kg_events"))

# Keep in sync with bpf/kg_common.h
MODE_AUDIT, MODE_ENFORCE = 0, 1
SENS_TAINT, SENS_DENY = 1, 2
NAME_LEN = 32
MANAGED_MAPS = ("sensitive_names", "exec_allow", "egress_allow")
HOOK_NAMES = {1: "exec", 2: "file_open", 3: "connect", 4: "sendmsg", 5: "bpf", 6: "ptrace"}
VERDICT_NAMES = {0: "allow", 1: "deny", 2: "audit_deny", 3: "taint"}


class PolicyError(Exception):
    """The policy file is invalid or refers to something that does not exist."""


class CtlError(Exception):
    """An operational error (not root, not loaded, ...)."""


# --------------------------------------------------------------------------
# Byte layouts (mirror bpf/kg_common.h; verified by tests/test_kgctl.py)
# --------------------------------------------------------------------------
def kdev(st_dev: int) -> int:
    """User-space st_dev -> kernel dev_t used in super_block->s_dev."""
    return (os.major(st_dev) << 20) | os.minor(st_dev)


def pack_cgroup_key(cgid: int) -> bytes:
    return struct.pack("<Q", cgid)


def pack_agent_cfg(agent_id: int, mode: int, egress_default_deny: int, flags: int = 0) -> bytes:
    return struct.pack("<IIII", agent_id, mode, egress_default_deny, flags)


def pack_inode_key(ino: int, dev: int, agent_id: int) -> bytes:
    return struct.pack("<QII", ino, dev, agent_id)


def pack_egress_key(agent_id: int, ip: str, port: int) -> bytes:
    # address stays in NETWORK byte order (inet_aton), port is little-endian host order
    return struct.pack("<I", agent_id) + socket.inet_aton(ip) + struct.pack("<HH", port, 0)


def pack_name_key(name: str) -> bytes:
    raw = name.encode()[: NAME_LEN - 1]
    return raw.ljust(NAME_LEN, b"\0")


ONE = b"\x01"


# --------------------------------------------------------------------------
# Policy loading, validation and compilation
# --------------------------------------------------------------------------
def load_policy(path: str | os.PathLike) -> dict:
    import yaml  # imported lazily so `--help` works without PyYAML

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data


def file_sha256(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_policy(pol: object) -> None:
    """Raise PolicyError with a precise message for any structural problem."""
    if not isinstance(pol, dict):
        raise PolicyError("policy must be a YAML mapping")
    if pol.get("version") != 1:
        raise PolicyError("policy 'version' must be 1")

    agents = pol.get("agents")
    if not isinstance(agents, dict) or not agents:
        raise PolicyError("policy needs a non-empty 'agents' mapping")

    seen_ids: dict[int, str] = {}
    for name, a in agents.items():
        where = f"agents.{name}"
        if not isinstance(a, dict):
            raise PolicyError(f"{where} must be a mapping")
        aid = a.get("id")
        if not isinstance(aid, int) or isinstance(aid, bool) or not 1 <= aid <= 63:
            raise PolicyError(f"{where}.id must be an integer 1..63")
        if aid in seen_ids:
            raise PolicyError(f"{where}.id={aid} already used by agents.{seen_ids[aid]}")
        seen_ids[aid] = name

        if a.get("mode") not in ("audit", "enforce"):
            raise PolicyError(f"{where}.mode must be 'audit' or 'enforce' (no default on purpose)")

        ex = a.get("exec")
        if not isinstance(ex, dict) or not isinstance(ex.get("allow"), list) or not ex["allow"]:
            raise PolicyError(f"{where}.exec.allow must be a non-empty list (deny-by-default: "
                              "the agent could not even start)")
        for i, ent in enumerate(ex["allow"]):
            if isinstance(ent, str):
                continue
            if isinstance(ent, dict) and isinstance(ent.get("path"), str):
                continue
            raise PolicyError(f"{where}.exec.allow[{i}] must be a path string or {{path, sha256}}")

        net = a.get("network", {})
        if not isinstance(net, dict):
            raise PolicyError(f"{where}.network must be a mapping")
        if net.get("egress_default", "deny") not in ("allow", "deny"):
            raise PolicyError(f"{where}.network.egress_default must be 'allow' or 'deny'")
        for i, ent in enumerate(net.get("allow", []) or []):
            if not isinstance(ent, dict) or not (("ip" in ent) ^ ("host" in ent)):
                raise PolicyError(f"{where}.network.allow[{i}] needs exactly one of 'ip' or 'host'")
            ports = ent.get("ports", [ent["port"]] if "port" in ent else None)
            if not ports:
                raise PolicyError(f"{where}.network.allow[{i}] needs 'port' / 'ports' (use 0 for any)")
            for p in ports:
                if not isinstance(p, int) or not 0 <= p <= 65535:
                    raise PolicyError(f"{where}.network.allow[{i}] invalid port {p!r}")

        lim = a.get("limits", {})
        if not isinstance(lim, dict):
            raise PolicyError(f"{where}.limits must be a mapping")
        for k in ("pids_max", "memory_max"):
            if k in lim and (not isinstance(lim[k], int) or lim[k] <= 0):
                raise PolicyError(f"{where}.limits.{k} must be a positive integer")

    sens = pol.get("sensitive", {}) or {}
    if not isinstance(sens, dict):
        raise PolicyError("'sensitive' must be a mapping with 'taint' and/or 'deny' lists")
    names: dict[str, str] = {}
    for kind in ("taint", "deny"):
        for n in sens.get(kind, []) or []:
            if not isinstance(n, str) or not n or "/" in n:
                raise PolicyError(f"sensitive.{kind}: {n!r} must be a plain file name (no '/')")
            if len(n.encode()) > NAME_LEN - 1:
                raise PolicyError(f"sensitive.{kind}: {n!r} longer than {NAME_LEN - 1} bytes")
            if n in names and names[n] != kind:
                raise PolicyError(f"sensitive: {n!r} is listed as both taint and deny")
            names[n] = kind


def _resolve_exec(entry) -> tuple[str, os.stat_result]:
    path, want_sha = (entry, None) if isinstance(entry, str) else (entry["path"], entry.get("sha256"))
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except FileNotFoundError:
        raise PolicyError(f"exec.allow: {path} does not exist") from None
    if not stat.S_ISREG(st.st_mode):
        raise PolicyError(f"exec.allow: {real} is not a regular file")
    if not st.st_mode & 0o111:
        raise PolicyError(f"exec.allow: {real} is not executable")
    if want_sha and file_sha256(real) != want_sha.lower():
        raise PolicyError(f"exec.allow: sha256 mismatch for {real} "
                          "(binary was changed or the policy hash is stale)")
    return real, st


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


def build_plan(pol: dict, resolver=_default_resolver) -> dict:
    """
    Turn a validated policy into map entries.  Pure function apart from stat()
    of the allow-listed binaries and the (injectable) DNS resolver.

    Returns {"maps": {map_name: [(key_bytes, value_bytes), ...]},
             "agents": {name: {...}}, "notes": [str, ...]}
    """
    validate_policy(pol)
    maps: dict[str, list[tuple[bytes, bytes]]] = {m: [] for m in MANAGED_MAPS}
    notes: list[str] = []
    agents: dict[str, dict] = {}

    sens = pol.get("sensitive", {}) or {}
    for n in sens.get("taint", []) or []:
        maps["sensitive_names"].append((pack_name_key(n), bytes([SENS_TAINT])))
    for n in sens.get("deny", []) or []:
        maps["sensitive_names"].append((pack_name_key(n), bytes([SENS_DENY])))

    for name, a in pol["agents"].items():
        aid = a["id"]
        net = a.get("network", {}) or {}
        egress_default_deny = 1 if net.get("egress_default", "deny") == "deny" else 0
        agents[name] = {"id": aid, "mode": a["mode"], "egress_default_deny": egress_default_deny,
                        "run_as": a.get("run_as", "nobody"), "workdir": a.get("workdir", "/tmp"),
                        "limits": a.get("limits", {}) or {},
                        "env_passthrough": a.get("env_passthrough", []) or []}

        for ent in a["exec"]["allow"]:
            real, st = _resolve_exec(ent)
            maps["exec_allow"].append((pack_inode_key(st.st_ino, kdev(st.st_dev), aid), ONE))
            if st.st_nlink > 1:
                notes.append(f"{name}: {real} has {st.st_nlink} hard links; every name for it is allowed")

        for ent in net.get("allow", []) or []:
            ports = ent.get("ports", [ent["port"]] if "port" in ent else [])
            if "ip" in ent:
                try:
                    addrs = [str(ipaddress.IPv4Address(ent["ip"]))]
                except ValueError:
                    raise PolicyError(f"agents.{name}.network.allow: {ent['ip']!r} is not an IPv4 address "
                                      "(IPv6 allow-listing is not implemented yet)") from None
            else:
                try:
                    addrs = resolver(ent["host"])
                except OSError as exc:
                    raise PolicyError(f"agents.{name}.network.allow: cannot resolve {ent['host']}: {exc}") from None
                if not addrs:
                    raise PolicyError(f"agents.{name}.network.allow: {ent['host']} has no IPv4 address")
                notes.append(f"{name}: {ent['host']} -> {', '.join(addrs)} (re-run `apply` to refresh DNS)")
            for ip in addrs:
                for p in ports:
                    maps["egress_allow"].append((pack_egress_key(aid, ip, p), ONE))

        if a["mode"] == "audit":
            notes.append(f"{name}: AUDIT mode - violations are logged but NOT blocked")
        if egress_default_deny == 0:
            notes.append(f"{name}: egress_default=allow - network is only restricted after a sensitive read (taint)")

    return {"maps": maps, "agents": agents, "notes": notes}


# --------------------------------------------------------------------------
# bpftool plumbing
# --------------------------------------------------------------------------
def bpftool_bin() -> str:
    exe = os.environ.get("KG_BPFTOOL") or shutil.which("bpftool") or "/usr/sbin/bpftool"
    if not os.path.exists(exe):
        raise CtlError("bpftool not found (apt install linux-tools-common linux-tools-$(uname -r))")
    return exe


def bpftool(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run([bpftool_bin(), *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise CtlError(f"bpftool {' '.join(args[:3])} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def _hex(b: bytes) -> list[str]:
    return [f"{x:02x}" for x in b]


def map_path(name: str) -> str:
    p = MAPS_DIR / name
    if not p.exists():
        raise CtlError(f"map {name} not found at {p}; run `kgctl.py load` first")
    return str(p)


def map_update(name: str, key: bytes, value: bytes) -> None:
    bpftool("map", "update", "pinned", map_path(name), "key", "hex", *_hex(key), "value", "hex", *_hex(value))


def map_delete(name: str, key: bytes) -> None:
    bpftool("map", "delete", "pinned", map_path(name), "key", "hex", *_hex(key), check=False)


# --------------------------------------------------------------------------
# State file (what we applied, which agents are running)
# --------------------------------------------------------------------------
def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


def need_root() -> None:
    if os.geteuid() != 0:
        raise CtlError("this command must run as root")


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------
def _kernel_version() -> tuple[int, int]:
    rel = os.uname().release.split("-")[0].split(".")
    return int(rel[0]), int(rel[1])


def _kernel_config_has(option: str) -> bool | None:
    for p in (Path("/proc/config.gz"), Path(f"/boot/config-{os.uname().release}")):
        try:
            if p.suffix == ".gz":
                import gzip
                text = gzip.open(p, "rt").read()
            else:
                text = p.read_text()
        except OSError:
            continue
        return f"{option}=y" in text
    return None


def cmd_doctor(args) -> int:
    results: list[tuple[str, str, str]] = []

    def add(level, what, detail=""):
        results.append((level, what, detail))

    add("OK" if os.geteuid() == 0 else "WARN", "running as root", "needed for load/apply/run")
    major, minor = _kernel_version()
    add("OK" if (major, minor) >= (5, 15) else "FAIL", f"kernel {major}.{minor}", "need >= 5.15")
    try:
        lsm = Path("/sys/kernel/security/lsm").read_text().strip()
        add("OK" if "bpf" in lsm.split(",") else "FAIL", "'bpf' in active LSM list", lsm +
            ("" if "bpf" in lsm.split(",") else "  -> add lsm=...,bpf to the kernel command line and reboot"))
    except OSError:
        add("WARN", "cannot read /sys/kernel/security/lsm", "mount securityfs?")
    cfg = _kernel_config_has("CONFIG_BPF_LSM")
    add("OK" if cfg else ("WARN" if cfg is None else "FAIL"), "CONFIG_BPF_LSM=y",
        "kernel config not readable" if cfg is None else "")
    add("OK" if Path("/sys/kernel/btf/vmlinux").exists() else "FAIL", "kernel BTF (CO-RE)", "/sys/kernel/btf/vmlinux")
    add("OK" if (CGROUP_ROOT / "cgroup.controllers").exists() else "FAIL", "cgroup v2 unified hierarchy", str(CGROUP_ROOT))
    add("OK" if (major, minor) >= (5, 14) else "WARN", "cgroup.kill available (>= 5.14)", "used for the `kill` tier")
    try:
        bpftool_bin()
        add("OK", "bpftool present")
    except CtlError as exc:
        add("FAIL", "bpftool present", str(exc))
    mounted = any(line.split()[2:3] == ["bpf"] for line in Path("/proc/mounts").read_text().splitlines())
    add("OK" if mounted else "FAIL", "bpffs mounted", "mount -t bpf bpf /sys/fs/bpf")
    add("OK" if BPF_OBJ.exists() else "FAIL", "BPF object built", f"{BPF_OBJ}  (run `make`)")
    add("OK" if EVENTS_BIN.exists() else "WARN", "kg_events built", f"{EVENTS_BIN}")
    try:
        pwd.getpwnam("kgagent")
        add("OK", "unprivileged user 'kgagent'")
    except KeyError:
        add("WARN", "unprivileged user 'kgagent'", "useradd --system --no-create-home kgagent")

    width = max(len(w) for _, w, _ in results)
    for level, what, detail in results:
        print(f"[{level:4}] {what:<{width}}  {detail}")
    return 1 if any(r[0] == "FAIL" for r in results) else 0


# --------------------------------------------------------------------------
# plan / load / apply / unload
# --------------------------------------------------------------------------
def _print_plan(plan: dict) -> None:
    for name, a in plan["agents"].items():
        print(f"agent {name}: id={a['id']} mode={a['mode']} egress_default_deny={a['egress_default_deny']} "
              f"run_as={a['run_as']} limits={a['limits']}")
    for m, entries in plan["maps"].items():
        print(f"  map {m:16} {len(entries)} entries")
    for n in plan["notes"]:
        print(f"  note: {n}")


def cmd_plan(args) -> int:
    pol = load_policy(args.policy)
    plan = build_plan(pol)
    _print_plan(plan)
    print("policy OK (nothing was loaded)")
    return 0


def cmd_load(args) -> int:
    need_root()
    if not BPF_OBJ.exists():
        raise CtlError(f"{BPF_OBJ} missing; run `make` in zta_v2/")
    if PROGS_DIR.exists():
        raise CtlError("already loaded; run `kgctl.py unload` first")
    BPFFS_ROOT.mkdir(parents=True, exist_ok=True)
    MAPS_DIR.mkdir(exist_ok=True)
    bpftool("prog", "loadall", str(BPF_OBJ), str(PROGS_DIR), "pinmaps", str(MAPS_DIR), "autoattach")
    n_prog = len([p for p in PROGS_DIR.iterdir() if not p.name.endswith("_link")])
    print(f"loaded {n_prog} LSM programs; maps pinned in {MAPS_DIR}")
    print("NOTE: with no policy applied and no agent registered, KernelGuard changes nothing.")
    return 0


def cmd_apply(args) -> int:
    need_root()
    path = os.path.abspath(args.policy)
    pol = load_policy(path)
    plan = build_plan(pol)
    state = load_state()
    applied_old = state.get("applied", {})
    applied_new: dict[str, list[str]] = {}

    for m in MANAGED_MAPS:
        entries = plan["maps"][m]
        new_keys = {k.hex(): v for k, v in entries}
        for kh, v in new_keys.items():          # add/refresh first ...
            map_update(m, bytes.fromhex(kh), v)
        for stale in set(applied_old.get(m, [])) - set(new_keys):   # ... then remove stale
            map_delete(m, bytes.fromhex(stale))
        applied_new[m] = sorted(new_keys)

    state.update({"applied": applied_new, "policy_path": path, "policy_sha256": file_sha256(path),
                  "agents": plan["agents"], "applied_at": int(time.time())})
    state.setdefault("runs", {})
    save_state(state)
    _print_plan(plan)
    print(f"applied policy {path} (sha256 {state['policy_sha256'][:12]}...)")
    return 0


def cmd_unload(args) -> int:
    need_root()
    state = load_state()
    if state.get("runs") and not args.force:
        raise CtlError("agents are still registered; unloading would leave them UNCONFINED. "
                       "Stop them first or pass --force.")
    for d in (PROGS_DIR, MAPS_DIR):
        if d.exists():
            for p in d.iterdir():
                p.unlink()   # unlinking a pinned link detaches the program
            d.rmdir()
    if BPFFS_ROOT.exists():
        try:
            BPFFS_ROOT.rmdir()
        except OSError:
            pass
    state.pop("applied", None)
    save_state(state)
    print("unloaded")
    return 0


# --------------------------------------------------------------------------
# run: start an agent in its own cgroup
# --------------------------------------------------------------------------
def _write(path: Path, text: str) -> None:
    with open(path, "w") as fh:
        fh.write(text)


def _prepare_cgroup(agent: str, limits: dict) -> Path:
    KG_CGROUP.mkdir(exist_ok=True)
    for parent in (CGROUP_ROOT, KG_CGROUP):
        try:
            _write(parent / "cgroup.subtree_control", "+pids +memory")
        except OSError:
            pass  # already enabled, or not permitted: limits below become best effort
    cg = KG_CGROUP / f"{agent}-{os.getpid()}-{int(time.time())}"
    cg.mkdir()
    for key, fname in (("pids_max", "pids.max"), ("memory_max", "memory.max")):
        if key in limits:
            try:
                _write(cg / fname, str(limits[key]))
            except OSError as exc:
                print(f"warning: could not set {fname}: {exc}", file=sys.stderr)
    return cg


def _cgroup_empty(cg: Path) -> bool:
    try:
        return not (cg / "cgroup.procs").read_text().strip()
    except OSError:
        return True


def _kill_cgroup(cg: Path) -> None:
    try:
        _write(cg / "cgroup.kill", "1")
    except OSError:
        for line in (cg / "cgroup.procs").read_text().split():
            try:
                os.kill(int(line), signal.SIGKILL)
            except OSError:
                pass


def cmd_run(args) -> int:
    need_root()
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise CtlError("usage: kgctl.py run AGENT -- COMMAND [ARGS...]")

    state = load_state()
    policy_path = args.policy or state.get("policy_path")
    if not policy_path or "applied" not in state:
        raise CtlError("no policy applied; run `kgctl.py apply -p policy.yaml` first")
    if file_sha256(policy_path) != state.get("policy_sha256"):
        raise CtlError("policy file changed since `apply` - refusing to start (re-run apply to accept the change)")

    pol = load_policy(policy_path)
    # Re-validates the policy and re-checks binary hashes right now.  DNS is NOT needed here
    # (the egress map was filled by `apply`), so a resolver outage cannot stop an agent starting.
    plan = build_plan(pol, resolver=lambda host: ["0.0.0.0"])
    if args.agent not in plan["agents"]:
        raise CtlError(f"unknown agent {args.agent!r}; known: {', '.join(plan['agents'])}")
    a = plan["agents"][args.agent]
    mode = {"audit": MODE_AUDIT, "enforce": MODE_ENFORCE}[args.mode or a["mode"]]

    # ---- everything that may fail happens BEFORE the child joins the cgroup ----
    try:
        pw = pwd.getpwnam(a["run_as"])
    except KeyError:
        raise CtlError(f"run_as user {a['run_as']!r} does not exist (useradd --system {a['run_as']})") from None
    if pw.pw_uid == 0:
        raise CtlError("refusing to run an agent as root (set run_as to an unprivileged user)")
    workdir = Path(a["workdir"])
    workdir.mkdir(parents=True, exist_ok=True)
    os.chown(workdir, pw.pw_uid, pw.pw_gid)
    exe = shutil.which(cmd[0], path="/usr/bin:/bin:/usr/local/bin") if "/" not in cmd[0] else cmd[0]
    if not exe:
        raise CtlError(f"command {cmd[0]!r} not found")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(workdir), "LANG": "C.UTF-8", "KG_AGENT": args.agent,
           "KG_WORKDIR": str(workdir)}
    for var in a["env_passthrough"]:
        if var in os.environ:
            env[var] = os.environ[var]
    libc = ctypes.CDLL(None, use_errno=True)

    cg = _prepare_cgroup(args.agent, a["limits"])
    cgid = os.stat(cg).st_ino    # on cgroup2 the directory inode number IS the cgroup id
    map_update("agent_cgroups", pack_cgroup_key(cgid),
               pack_agent_cfg(a["id"], mode, a["egress_default_deny"]))
    state.setdefault("runs", {})[str(cgid)] = {"agent": args.agent, "cgroup": str(cg),
                                              "started": int(time.time()), "controller_pid": os.getpid()}
    save_state(state)
    print(f"[kgctl] agent={args.agent} id={a['id']} mode={'enforce' if mode else 'audit'} "
          f"cgroup={cg.name} cgid={cgid} exe={exe}", file=sys.stderr)

    pid = os.fork()
    if pid == 0:                                   # ------------------ child
        try:
            _write(cg / "cgroup.procs", str(os.getpid()))   # join cgroup while still root
            os.setgroups([])
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            if libc.prctl(38, 1, 0, 0, 0) != 0:        # PR_SET_NO_NEW_PRIVS
                raise OSError(ctypes.get_errno(), "prctl(NO_NEW_PRIVS) failed")
            os.chdir(workdir)
            os.execve(exe, cmd, env)
        except PermissionError:
            print(f"[kgctl] exec of {exe} was refused (EPERM). Is it in agents.{args.agent}.exec.allow?",
                  file=sys.stderr)
            os._exit(126)
        except BaseException as exc:  # noqa: BLE001 - child must never return into the parent's code
            print(f"[kgctl] child setup failed: {exc}", file=sys.stderr)
            os._exit(125)

    # ---------------------------------------------------------- parent
    def _terminate(signum, _frame):
        _kill_cgroup(cg)

    signal.signal(signal.SIGINT, _terminate)
    signal.signal(signal.SIGTERM, _terminate)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)

    # the agent may have left background children behind: kill and wait for an empty cgroup
    deadline = time.time() + 5
    while not _cgroup_empty(cg) and time.time() < deadline:
        _kill_cgroup(cg)
        time.sleep(0.05)
    map_delete("agent_cgroups", pack_cgroup_key(cgid))
    map_delete("agent_state", pack_cgroup_key(cgid))
    try:
        cg.rmdir()
    except OSError as exc:
        print(f"warning: could not remove {cg}: {exc}", file=sys.stderr)
    state = load_state()
    state.get("runs", {}).pop(str(cgid), None)
    save_state(state)
    return code


# --------------------------------------------------------------------------
# tier: graduated response (call this from risk_fusion.py)
# --------------------------------------------------------------------------
def _find_run(state: dict, who: str) -> tuple[int, dict]:
    runs = state.get("runs", {})
    if who in runs:
        return int(who), runs[who]
    match = [(int(k), v) for k, v in runs.items() if v["agent"] == who]
    if not match:
        raise CtlError(f"no running agent matching {who!r}")
    return max(match, key=lambda kv: kv[1]["started"])


def escalate(who: str, tier: str) -> str:
    """
    observe  - no change
    restrict - force ENFORCE mode and deny all non-listed egress
    freeze   - suspend every process of the agent (reversible with `thaw`)
    thaw     - undo freeze
    kill     - SIGKILL every process of the agent (cgroup.kill)
    """
    state = load_state()
    cgid, run = _find_run(state, who)
    cg = Path(run["cgroup"])
    agent = state["agents"][run["agent"]]
    if tier == "observe":
        return "no change"
    if tier == "restrict":
        map_update("agent_cgroups", pack_cgroup_key(cgid), pack_agent_cfg(agent["id"], MODE_ENFORCE, 1))
        return f"{run['agent']}: enforce + egress deny-all (except allow-list)"
    if tier == "freeze":
        _write(cg / "cgroup.freeze", "1")
        return f"{run['agent']}: frozen"
    if tier == "thaw":
        _write(cg / "cgroup.freeze", "0")
        return f"{run['agent']}: thawed"
    if tier == "kill":
        _kill_cgroup(cg)
        return f"{run['agent']}: killed"
    raise CtlError(f"unknown tier {tier!r}")


def cmd_tier(args) -> int:
    need_root()
    print(escalate(args.agent, args.tier))
    return 0


# --------------------------------------------------------------------------
# status / events
# --------------------------------------------------------------------------
def cmd_status(args) -> int:
    state = load_state()
    print(f"programs loaded : {PROGS_DIR.exists()}")
    if "applied" in state:
        print(f"policy          : {state.get('policy_path')} (sha256 {state.get('policy_sha256', '')[:12]}...)")
        for m, keys in state["applied"].items():
            print(f"  {m:16} {len(keys)} entries")
    runs = state.get("runs", {})
    print(f"running agents  : {len(runs)}")
    for cgid, r in runs.items():
        print(f"  {r['agent']:20} cgid={cgid} since {time.strftime('%F %T', time.localtime(r['started']))}")
    if PROGS_DIR.exists():
        proc = bpftool("-j", "map", "dump", "pinned", map_path("stats"), check=False)
        try:
            rows = json.loads(proc.stdout)
            print("decisions (hook/verdict: count)")
            for row in rows:
                row = row.get("formatted", row)
                idx = row["key"] if isinstance(row["key"], int) else int(row["key"][0], 16)
                total = sum(v["value"] for v in row["values"])
                if total:
                    print(f"  {HOOK_NAMES.get(idx // 8, idx // 8)}/{VERDICT_NAMES.get(idx % 8, idx % 8)}: {total}")
        except (ValueError, KeyError, TypeError):
            print("(could not parse counters; try: bpftool map dump pinned " + str(MAPS_DIR / "stats") + ")")
    return 0


def cmd_events(args) -> int:
    if not EVENTS_BIN.exists():
        raise CtlError(f"{EVENTS_BIN} missing; run `make`")
    os.execv(str(EVENTS_BIN), [str(EVENTS_BIN), str(MAPS_DIR / "events")])
    return 0  # not reached


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kgctl.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check this machine can run BPF-LSM enforcement").set_defaults(fn=cmd_doctor)

    s = sub.add_parser("plan", help="validate a policy and show what would be loaded (no root needed)")
    s.add_argument("-p", "--policy", required=True)
    s.set_defaults(fn=cmd_plan)

    sub.add_parser("load", help="load and attach the BPF-LSM programs").set_defaults(fn=cmd_load)

    s = sub.add_parser("apply", help="compile the policy into BPF maps")
    s.add_argument("-p", "--policy", required=True)
    s.set_defaults(fn=cmd_apply)

    s = sub.add_parser("run", help="run a command as a confined agent")
    s.add_argument("agent")
    s.add_argument("--policy", help="policy path (default: the one given to `apply`)")
    s.add_argument("--mode", choices=("audit", "enforce"), help="override the policy mode for this run")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("tier", help="graduated response for a running agent")
    s.add_argument("agent", help="agent name or cgroup id")
    s.add_argument("tier", choices=("observe", "restrict", "freeze", "thaw", "kill"))
    s.set_defaults(fn=cmd_tier)

    sub.add_parser("status", help="show loaded state").set_defaults(fn=cmd_status)
    sub.add_parser("events", help="stream decisions as JSON lines").set_defaults(fn=cmd_events)

    s = sub.add_parser("unload", help="detach the programs")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_unload)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (PolicyError, CtlError) as exc:
        print(f"kgctl: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
