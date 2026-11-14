#!/usr/bin/env python3
"""Micro-benchmark that runs INSIDE the (confined or unconfined) agent.  Standard library only.
Measures one-operation latency in nanoseconds for the four operations KernelGuard hooks:
  exec_true     posix_spawn(/usr/bin/true) + wait       -> bprm_check_security
  file_open     open('/etc/hostname') + close            -> file_open
  tcp_connect   connect() to a loopback listener         -> socket_connect
  udp_sendto    sendto() with an explicit loopback addr  -> socket_sendmsg
Prints ONE JSON line: {"ops": {op: [ns, ...]}, "errors": {op: n}}.
Any failed operation is counted, never timed, so a misconfigured policy cannot masquerade as speed."""
import argparse
import json
import os
import socket
import threading
import time

OPS = ("exec_true", "file_open", "tcp_connect", "udp_sendto")
TRUE = "/usr/bin/true"


def op_exec():
    pid = os.posix_spawn(TRUE, [TRUE], {})
    os.waitpid(pid, 0)


def op_open():
    fd = os.open("/etc/hostname", os.O_RDONLY)
    os.close(fd)


def make_tcp(port):
    def op():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", port))
        finally:
            s.close()
    return op


def make_udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def op():
        s.sendto(b"x", ("127.0.0.1", port))
    return op


def start_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(256)

    def drain():
        while True:
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                return
    threading.Thread(target=drain, daemon=True).start()
    return srv


def measure(fn, iters, warmup):
    for _ in range(warmup):
        fn()
    out, errors = [], 0
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        try:
            fn()
        except OSError:
            errors += 1
            continue
        out.append(time.perf_counter_ns() - t0)
    return out, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=2000)
    ap.add_argument("--exec-iters", type=int, default=0, help="default: iters // 4 (exec is slow)")
    ap.add_argument("--warmup", type=int, default=200)
    a = ap.parse_args()

    srv = start_listener()
    port = srv.getsockname()[1]
    udp_sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sink.bind(("127.0.0.1", 0))
    udp_port = udp_sink.getsockname()[1]
    udp_sink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)

    plan = {"exec_true": (op_exec, a.exec_iters or max(a.iters // 4, 50)),
            "file_open": (op_open, a.iters),
            "tcp_connect": (make_tcp(port), a.iters),
            "udp_sendto": (make_udp(udp_port), a.iters)}
    ops, errs = {}, {}
    for name in OPS:
        fn, n = plan[name]
        ops[name], errs[name] = measure(fn, n, a.warmup)
    print(json.dumps({"ops": ops, "errors": errs}), flush=True)


if __name__ == "__main__":
    main()
