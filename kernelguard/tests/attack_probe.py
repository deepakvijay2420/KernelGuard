#!/usr/bin/env python3
"""
Runs INSIDE a confined agent (started by kgctl.py run ... via bypass_suite.sh) and tries
to get around the policy.  Each attempt prints one JSON line:

    {"name": "...", "expect": "blocked|allowed", "errno": 1, "passed": true}

Exit code 0 only if every attempt behaved as expected.

Scenarios
  strict : egress_default=deny agent.  Exec / file / network / ptrace bypass attempts.
  taint  : egress_default=allow agent. Proves the stateful rule:
           connect works BEFORE reading a secret and is refused AFTER.

An attempt "is blocked" only if it fails with EPERM, the errno the LSM returns, so a plain
Unix permission error (EACCES) is not mistaken for KernelGuard working.
"""
import argparse
import ctypes
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import time

WORK = os.environ.get("KG_WORKDIR", "/tmp")
RESULTS = []


def record(name, expect, err):
    """err: errno of the failure, or 0 if the operation succeeded."""
    if expect == "blocked":
        passed = err == errno.EPERM
    else:
        passed = err == 0
    RESULTS.append(passed)
    print(json.dumps({"name": name, "expect": expect, "errno": err, "passed": passed}), flush=True)


def attempt(name, expect, fn):
    try:
        fn()
        err = 0
    except OSError as exc:
        err = exc.errno or -1
    except subprocess.SubprocessError:
        err = -2
    record(name, expect, err)


def run(argv):
    subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def exec_tests():
    attempt("control: allow-listed /usr/bin/ls runs", "allowed", lambda: run(["/usr/bin/ls", WORK]))

    attempt("exec /bin/sh (not in allow-list)", "blocked", lambda: run(["/bin/sh", "-c", "true"]))
    attempt("exec /bin/bash", "blocked", lambda: run(["/bin/bash", "-c", "true"]))
    attempt("exec via path traversal /usr/bin/../../bin/sh", "blocked",
            lambda: run(["/usr/bin/../../bin/sh", "-c", "true"]))

    link = os.path.join(WORK, "sh_link")
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink("/bin/sh", link)
    attempt("exec symlink -> /bin/sh", "blocked", lambda: run([link, "-c", "true"]))

    ok_link = os.path.join(WORK, "ls_link")
    if os.path.lexists(ok_link):
        os.unlink(ok_link)
    os.symlink("/usr/bin/ls", ok_link)
    attempt("control: symlink -> allowed inode still runs", "allowed", lambda: run([ok_link, WORK]))

    copy = os.path.join(WORK, "ls_copy")
    shutil.copy("/usr/bin/ls", copy)
    os.chmod(copy, 0o755)
    attempt("exec COPY of an allowed binary (new inode)", "blocked", lambda: run([copy, WORK]))

    def memfd_exec():
        fd = os.memfd_create("evil")
        with open("/usr/bin/ls", "rb") as src:
            os.write(fd, src.read())
        pid = os.fork()
        if pid == 0:
            try:
                os.execve(f"/proc/self/fd/{fd}", ["evil"], {})
            except OSError as exc:
                os._exit(exc.errno or 255)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        if code:
            raise OSError(code, "memfd exec refused")
    attempt("exec from memfd (fileless)", "blocked", memfd_exec)


def file_tests():
    shadow = os.path.join(WORK, "shadow")
    with open(shadow, "w") as fh:
        fh.write("not really a shadow file\n")
    attempt("open file named 'shadow' (deny list)", "blocked", lambda: open(shadow).read())

    alias = os.path.join(WORK, "innocent_name")
    if os.path.lexists(alias):
        os.unlink(alias)
    os.symlink(shadow, alias)
    attempt("open 'shadow' through an innocent symlink name", "blocked", lambda: open(alias).read())


def net_tests_strict():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def tcp():
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.close()
    attempt("TCP connect to non-allow-listed 127.0.0.1", "blocked", tcp)

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"exfil", ("192.0.2.1", 9))     # TEST-NET-1, never routed
    attempt("UDP sendto (no connect) to 192.0.2.1", "blocked", udp)

    def v6():
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("::1", port))
    attempt("TCP connect over IPv6 (no v6 allow-list)", "blocked", v6)
    srv.close()


def net_tests_taint():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def tcp():
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.close()

    attempt("control: connect BEFORE touching a secret", "allowed", tcp)

    env = os.path.join(WORK, ".env")
    with open(env, "w") as fh:
        fh.write("API_KEY=dummy\n")
    attempt("control: reading .env itself is allowed (taint only)", "allowed", lambda: open(env).read())
    time.sleep(0.05)
    attempt("connect AFTER reading .env (tainted)", "blocked", tcp)
    srv.close()


def misc_tests():
    libc = ctypes.CDLL(None, use_errno=True)

    def ptrace_child():
        pid = os.fork()
        if pid == 0:
            time.sleep(5)
            os._exit(0)
        try:
            ctypes.set_errno(0)
            rc = libc.ptrace(16, pid, None, None)   # PTRACE_ATTACH
            if rc == -1:
                raise OSError(ctypes.get_errno(), "ptrace refused")
        finally:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    attempt("ptrace(PTRACE_ATTACH) own child", "blocked", ptrace_child)

    def bpf_call():
        ctypes.set_errno(0)
        rc = libc.syscall(321, 0, None, 0)           # SYS_bpf (x86_64), BPF_MAP_CREATE with junk attr
        if rc == -1:
            raise OSError(ctypes.get_errno(), "bpf refused")
    attempt("bpf() syscall", "blocked", bpf_call)

    # Cgroup migration is controlled by cgroup filesystem permissions and
    # delegation.  A normal unprivileged agent usually receives EACCES before
    # any BPF-LSM decision is involved, so this is deliberately NOT counted as
    # a KernelGuard enforcement result.  Validate cgroup membership separately
    # from the host-side controller and record it in the test report.


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=("strict", "taint"), required=True)
    args = ap.parse_args()
    os.makedirs(WORK, exist_ok=True)

    if args.scenario == "strict":
        exec_tests()
        file_tests()
        net_tests_strict()
        misc_tests()
    else:
        net_tests_taint()

    ok = all(RESULTS)
    print(json.dumps({"summary": True, "total": len(RESULTS), "passed": sum(RESULTS), "ok": ok}), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
