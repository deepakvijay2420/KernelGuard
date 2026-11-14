#!/usr/bin/env python3

import csv
import os
import random
import re
import subprocess
import time
from pathlib import Path

BASE = Path("/tmp/kernelguard-ml-lab")
LOG = Path.home() / "kernelguard/logs/kernelguard_live.log"

OUT_DIR = Path.home() / "kernelguard/dataset/ml_v2/benign"
RAW_DIR = OUT_DIR / "raw"
CSV_FILE = OUT_DIR / "benign_events.csv"
META_FILE = OUT_DIR / "benign_runs.csv"

BASE.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------
# Controlled files
# ------------------------------------------------------------

(BASE / "README.txt").write_text(
    "KernelGuard benign ML dataset\n"
    "Controlled research workload\n"
    "Agent runtime security experiment\n"
)

(BASE / "research.txt").write_text(
    "KernelGuard Research Notes\n"
    "Agentic AI runtime security\n"
    "eBPF Linux monitoring\n"
    "Zero Trust Architecture\n"
    "Behavioral analysis\n"
)

(BASE / "data.txt").write_text(
    "\n".join([
        "alpha",
        "beta",
        "gamma",
        "delta",
        "epsilon",
        "alpha",
        "beta",
        "gamma",
    ])
)

(BASE / "numbers.txt").write_text(
    "\n".join(str(i) for i in range(1, 101))
)

# ------------------------------------------------------------
# Commands that belong to our controlled workloads
# ------------------------------------------------------------

KNOWN_PATHS = {
    "/bin/pwd",
    "/bin/ls",
    "/bin/cat",
    "/usr/bin/head",
    "/usr/bin/tail",
    "/usr/bin/wc",
    "/usr/bin/grep",
    "/usr/bin/sort",
    "/usr/bin/uniq",
    "/usr/bin/cut",
    "/usr/bin/tr",
    "/usr/bin/file",
    "/usr/bin/stat",
    "/usr/bin/du",
    "/usr/bin/sha256sum",
    "/usr/bin/md5sum",
    "/usr/bin/echo",
    "/usr/bin/printf",
    "/usr/bin/mkdir",
    "/usr/bin/touch",
    "/usr/bin/cp",
    "/usr/bin/mv",
    "/usr/bin/rm",
    "/usr/bin/uname",
    "/usr/bin/hostname",
    "/usr/bin/date",
    "/usr/bin/uptime",
    "/usr/bin/free",
    "/usr/bin/df",
    "/usr/bin/id",
    "/usr/bin/find",
    "/usr/bin/awk",
    "/usr/bin/sed",
    "/usr/bin/tar",
    "/usr/bin/gzip",
    "/usr/bin/sleep",
    "/usr/bin/true",
    "/usr/bin/false",
}

# ------------------------------------------------------------
# 40 benign task types
# ------------------------------------------------------------

TASKS = [

    ("file_listing", [
        ["/bin/ls", "-la", str(BASE)]
    ]),

    ("read_readme", [
        ["/bin/cat", str(BASE / "README.txt")]
    ]),

    ("read_research", [
        ["/bin/cat", str(BASE / "research.txt")]
    ]),

    ("read_data", [
        ["/bin/cat", str(BASE / "data.txt")]
    ]),

    ("head_file", [
        ["/usr/bin/head", "-5", str(BASE / "numbers.txt")]
    ]),

    ("tail_file", [
        ["/usr/bin/tail", "-5", str(BASE / "numbers.txt")]
    ]),

    ("count_lines", [
        ["/usr/bin/wc", "-l", str(BASE / "numbers.txt")]
    ]),

    ("search_kernelguard", [
        ["/usr/bin/grep", "KernelGuard", str(BASE / "README.txt")]
    ]),

    ("search_agent", [
        ["/usr/bin/grep", "Agentic", str(BASE / "research.txt")]
    ]),

    ("sort_data", [
        ["/usr/bin/sort", str(BASE / "data.txt")]
    ]),

    ("unique_data", [
        ["/usr/bin/sort", str(BASE / "data.txt")],
        ["/usr/bin/uniq"]
    ]),

    ("cut_data", [
        ["/usr/bin/cut", "-d", " ", "-f", "1", str(BASE / "research.txt")]
    ]),

    ("translate_text", [
        ["/usr/bin/tr", "a-z", "A-Z"]
    ]),

    ("file_type", [
        ["/usr/bin/file", str(BASE / "README.txt")]
    ]),

    ("file_stat", [
        ["/usr/bin/stat", str(BASE / "README.txt")]
    ]),

    ("disk_usage", [
        ["/usr/bin/du", "-sh", str(BASE)]
    ]),

    ("sha256_integrity", [
        ["/usr/bin/sha256sum", str(BASE / "README.txt")]
    ]),

    ("md5_integrity", [
        ["/usr/bin/md5sum", str(BASE / "README.txt")]
    ]),

    ("print_message", [
        ["/usr/bin/echo", "KernelGuard benign task"]
    ]),

    ("print_status", [
        ["/usr/bin/printf", "KernelGuard status OK\\n"]
    ]),

    ("system_pwd", [
        ["/bin/pwd"]
    ]),

    ("system_uname", [
        ["/usr/bin/uname", "-a"]
    ]),

    ("system_hostname", [
        ["/usr/bin/hostname"]
    ]),

    ("system_date", [
        ["/usr/bin/date"]
    ]),

    ("system_uptime", [
        ["/usr/bin/uptime"]
    ]),

    ("system_memory", [
        ["/usr/bin/free", "-h"]
    ]),

    ("system_disk", [
        ["/usr/bin/df", "-h", str(BASE)]
    ]),

    ("system_identity", [
        ["/usr/bin/id"]
    ]),

    ("find_files", [
        ["/usr/bin/find", str(BASE), "-maxdepth", "1", "-type", "f"]
    ]),

    ("awk_analysis", [
        ["/usr/bin/awk", "{print $1}", str(BASE / "data.txt")]
    ]),

    ("sed_analysis", [
        ["/usr/bin/sed", "-n", "1,3p", str(BASE / "research.txt")]
    ]),

    ("create_directory", [
        ["/usr/bin/mkdir", "-p", str(BASE / "temporary")]
    ]),

    ("create_file", [
        ["/usr/bin/touch", str(BASE / "temporary.txt")]
    ]),

    ("copy_file", [
        ["/usr/bin/cp", str(BASE / "README.txt"),
         str(BASE / "temporary_copy.txt")]
    ]),

    ("move_file", [
        ["/usr/bin/mv", str(BASE / "temporary_copy.txt"),
         str(BASE / "temporary_moved.txt")]
    ]),

    ("remove_file", [
        ["/usr/bin/rm", "-f", str(BASE / "temporary_moved.txt")]
    ]),

    ("archive_files", [
        ["/usr/bin/tar", "-cf",
         str(BASE / "research.tar"),
         "-C", str(BASE), "README.txt", "research.txt"]
    ]),

    ("gzip_archive", [
        ["/usr/bin/gzip", "-f", str(BASE / "research.tar")]
    ]),

    ("short_sleep", [
        ["/usr/bin/sleep", "0.1"]
    ]),

    ("true_command", [
        ["/usr/bin/true"]
    ]),

]

assert len(TASKS) == 40

# ------------------------------------------------------------
# Execute one command
# ------------------------------------------------------------

def execute(cmd):
    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False
        )
    except Exception:
        pass


# ------------------------------------------------------------
# Read newly appended log lines
# ------------------------------------------------------------

def read_new_lines(start_offset):
    try:
        with LOG.open("r", errors="replace") as f:
            f.seek(start_offset)
            return f.readlines()
    except Exception:
        return []


# ------------------------------------------------------------
# Parse KernelGuard log
# ------------------------------------------------------------

pattern = re.compile(
    r"PID=(\d+) \| UID=(\d+) \| PROCESS=(.*?) "
    r"\| PATH=(.*?) \| RISK=(.*?) "
    r"\| REASON=(.*?) \| ACTION=(.*)"
)

def parse_line(line):
    match = pattern.match(line.strip())

    if not match:
        return None

    pid, uid, process, path, risk, reason, action = match.groups()

    return {
        "pid": int(pid),
        "uid": int(uid),
        "process": process,
        "path": path,
        "risk": risk,
        "reason": reason,
        "action": action,
    }


# ------------------------------------------------------------
# Dataset output
# ------------------------------------------------------------

event_rows = []
run_rows = []

print()
print("=" * 70)
print(" KernelGuard — Clean Benign Dataset Generator")
print("=" * 70)
print()
print("Tasks :", len(TASKS))
print("Runs  : 10 per task")
print("Total planned workloads :", len(TASKS) * 10)
print()
print("Log :", LOG)
print()

if not LOG.exists():
    print("[ERROR] KernelGuard log does not exist:")
    print(LOG)
    raise SystemExit(1)

# Keep the existing log intact.
# We use file offsets so only newly generated events are collected.

with LOG.open("r", errors="replace") as f:
    initial_offset = f.seek(0, os.SEEK_END)

print("[+] Starting controlled experiment...")
print()

run_number = 0

for task_id, commands in TASKS:

    for repetition in range(1, 11):

        run_number += 1

        run_id = f"B{run_number:04d}"

        with LOG.open("r", errors="replace") as f:
            start_offset = f.seek(0, os.SEEK_END)

        start_time = time.time()

        # Execute task commands
        for cmd in commands:

            # stdin-style commands such as tr need controlled input
            if cmd[0] == "/usr/bin/tr":
                subprocess.run(
                    cmd,
                    input="KernelGuard benign dataset\n",
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False
                )
            elif cmd[0] == "/usr/bin/uniq":
                subprocess.run(
                    cmd,
                    input="alpha\nalpha\nbeta\nbeta\ngamma\n",
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False
                )
            else:
                execute(cmd)

        time.sleep(0.15)

        end_time = time.time()

        lines = read_new_lines(start_offset)

        parsed = []

        for line in lines:

            event = parse_line(line)

            if event is None:
                continue

            # Only keep commands belonging to our controlled vocabulary.
            if event["path"] not in KNOWN_PATHS:
                continue

            event["run_id"] = run_id
            event["task_id"] = task_id
            event["repetition"] = repetition
            event["label"] = "benign"
            event["timestamp_start"] = start_time
            event["timestamp_end"] = end_time

            parsed.append(event)
            event_rows.append(event)

        run_rows.append({
            "run_id": run_id,
            "task_id": task_id,
            "repetition": repetition,
            "label": "benign",
            "event_count": len(parsed),
            "duration_sec": round(end_time - start_time, 4),
        })

        print(
            f"[{run_number:03d}/400] "
            f"{task_id:<24} "
            f"run={repetition:02d} "
            f"events={len(parsed)}"
        )

print()
print("=" * 70)
print(" Dataset generation completed")
print("=" * 70)
print()
print("Total events:", len(event_rows))
print("Total runs  :", len(run_rows))
print()

# ------------------------------------------------------------
# Save event CSV
# ------------------------------------------------------------

event_fields = [
    "run_id",
    "task_id",
    "repetition",
    "label",
    "pid",
    "uid",
    "process",
    "path",
    "risk",
    "reason",
    "action",
    "timestamp_start",
    "timestamp_end",
]

with CSV_FILE.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=event_fields)
    writer.writeheader()
    writer.writerows(event_rows)

# ------------------------------------------------------------
# Save run metadata
# ------------------------------------------------------------

run_fields = [
    "run_id",
    "task_id",
    "repetition",
    "label",
    "event_count",
    "duration_sec",
]

with META_FILE.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=run_fields)
    writer.writeheader()
    writer.writerows(run_rows)

print("Events CSV:")
print(CSV_FILE)

print()
print("Run metadata:")
print(META_FILE)

print()
print("Next step: inspect dataset statistics before creating attacks.")
