#!/usr/bin/env python3

import csv
import os
import re
import subprocess
import time
from pathlib import Path

BASE = Path("/tmp/kernelguard-ml-lab")
REPO_ROOT = Path(__file__).resolve().parents[3]\nLOG = REPO_ROOT / "logs/kernelguard_live.log"

OUT_DIR = REPO_ROOT / "kernelguard/dataset/benign"
CSV_FILE = OUT_DIR / "benign_composite_events.csv"
META_FILE = OUT_DIR / "benign_composite_runs.csv"

BASE.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------
# Controlled files
# ------------------------------------------------------------

(BASE / "README.txt").write_text(
    "KernelGuard benign composite workload\n"
    "Agentic AI runtime security\n"
    "eBPF monitoring\n"
    "Zero Trust Architecture\n"
)

(BASE / "research.txt").write_text(
    "KernelGuard\n"
    "Agentic AI\n"
    "Linux Security\n"
    "eBPF\n"
    "Zero Trust\n"
    "Behavioral Analysis\n"
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
        "delta",
        "epsilon",
    ])
)

# ------------------------------------------------------------
# Commands allowed in the benign experiment
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
}

# ------------------------------------------------------------
# Multi-step benign workflows
# ------------------------------------------------------------

WORKFLOWS = [

    (
        "research_inspection",
        [
            ["/bin/ls", "-la", str(BASE)],
            ["/bin/cat", str(BASE / "README.txt")],
            ["/usr/bin/grep", "KernelGuard", str(BASE / "README.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "README.txt")],
        ],
    ),

    (
        "research_analysis",
        [
            ["/bin/cat", str(BASE / "research.txt")],
            ["/usr/bin/grep", "eBPF", str(BASE / "research.txt")],
            ["/usr/bin/sort", str(BASE / "research.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "research.txt")],
        ],
    ),

    (
        "file_integrity",
        [
            ["/bin/ls", str(BASE)],
            ["/usr/bin/stat", str(BASE / "README.txt")],
            ["/usr/bin/sha256sum", str(BASE / "README.txt")],
            ["/usr/bin/md5sum", str(BASE / "README.txt")],
        ],
    ),

    (
        "data_processing",
        [
            ["/bin/cat", str(BASE / "data.txt")],
            ["/usr/bin/sort", str(BASE / "data.txt")],
            ["/usr/bin/uniq", str(BASE / "data.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "data.txt")],
        ],
    ),

    (
        "system_information",
        [
            ["/usr/bin/uname", "-a"],
            ["/usr/bin/hostname"],
            ["/usr/bin/date"],
            ["/usr/bin/uptime"],
            ["/usr/bin/id"],
        ],
    ),

    (
        "storage_information",
        [
            ["/usr/bin/df", "-h", str(BASE)],
            ["/usr/bin/du", "-sh", str(BASE)],
            ["/bin/ls", "-lh", str(BASE)],
        ],
    ),

    (
        "file_metadata",
        [
            ["/usr/bin/file", str(BASE / "README.txt")],
            ["/usr/bin/stat", str(BASE / "README.txt")],
            ["/usr/bin/du", "-h", str(BASE / "README.txt")],
        ],
    ),

    (
        "text_statistics",
        [
            ["/bin/cat", str(BASE / "research.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "research.txt")],
            ["/usr/bin/head", "-3", str(BASE / "research.txt")],
            ["/usr/bin/tail", "-3", str(BASE / "research.txt")],
        ],
    ),

    (
        "search_workflow",
        [
            ["/usr/bin/find", str(BASE), "-maxdepth", "1", "-type", "f"],
            ["/usr/bin/grep", "KernelGuard", str(BASE / "README.txt")],
            ["/usr/bin/stat", str(BASE / "README.txt")],
        ],
    ),

    (
        "report_preparation",
        [
            ["/bin/ls", str(BASE)],
            ["/bin/cat", str(BASE / "README.txt")],
            ["/usr/bin/head", "-5", str(BASE / "research.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "research.txt")],
        ],
    ),

    (
        "checksum_workflow",
        [
            ["/usr/bin/sha256sum", str(BASE / "README.txt")],
            ["/usr/bin/sha256sum", str(BASE / "research.txt")],
            ["/usr/bin/md5sum", str(BASE / "README.txt")],
        ],
    ),

    (
        "directory_inspection",
        [
            ["/bin/pwd"],
            ["/bin/ls", "-la", str(BASE)],
            ["/usr/bin/find", str(BASE), "-maxdepth", "1", "-type", "f"],
            ["/usr/bin/du", "-sh", str(BASE)],
        ],
    ),

    (
        "controlled_file_creation",
        [
            ["/usr/bin/mkdir", "-p", str(BASE / "work")],
            ["/usr/bin/touch", str(BASE / "work" / "notes.txt")],
            ["/usr/bin/stat", str(BASE / "work" / "notes.txt")],
            ["/usr/bin/rm", "-f", str(BASE / "work" / "notes.txt")],
        ],
    ),

    (
        "controlled_copy",
        [
            ["/usr/bin/cp", str(BASE / "README.txt"),
             str(BASE / "copy.txt")],
            ["/usr/bin/stat", str(BASE / "copy.txt")],
            ["/usr/bin/sha256sum", str(BASE / "copy.txt")],
            ["/usr/bin/rm", "-f", str(BASE / "copy.txt")],
        ],
    ),

    (
        "controlled_move",
        [
            ["/usr/bin/touch", str(BASE / "move_source.txt")],
            ["/usr/bin/mv",
             str(BASE / "move_source.txt"),
             str(BASE / "move_target.txt")],
            ["/usr/bin/stat", str(BASE / "move_target.txt")],
            ["/usr/bin/rm", "-f", str(BASE / "move_target.txt")],
        ],
    ),

    (
        "archive_workflow",
        [
            ["/usr/bin/tar", "-cf",
             str(BASE / "sample.tar"),
             "-C", str(BASE),
             "README.txt", "research.txt"],
            ["/usr/bin/stat", str(BASE / "sample.tar")],
            ["/usr/bin/sha256sum", str(BASE / "sample.tar")],
            ["/usr/bin/rm", "-f", str(BASE / "sample.tar")],
        ],
    ),

    (
        "awk_sed_analysis",
        [
            ["/usr/bin/awk", "{print $1}", str(BASE / "data.txt")],
            ["/usr/bin/sed", "-n", "1,3p",
             str(BASE / "research.txt")],
            ["/usr/bin/wc", "-l",
             str(BASE / "research.txt")],
        ],
    ),

    (
        "multi_file_read",
        [
            ["/bin/cat", str(BASE / "README.txt")],
            ["/bin/cat", str(BASE / "research.txt")],
            ["/bin/cat", str(BASE / "data.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "data.txt")],
        ],
    ),

    (
        "integrity_and_metadata",
        [
            ["/usr/bin/stat", str(BASE / "README.txt")],
            ["/usr/bin/file", str(BASE / "README.txt")],
            ["/usr/bin/sha256sum", str(BASE / "README.txt")],
            ["/usr/bin/md5sum", str(BASE / "README.txt")],
        ],
    ),

    (
        "complete_research_check",
        [
            ["/bin/ls", "-la", str(BASE)],
            ["/bin/cat", str(BASE / "README.txt")],
            ["/bin/cat", str(BASE / "research.txt")],
            ["/usr/bin/grep", "Security", str(BASE / "research.txt")],
            ["/usr/bin/wc", "-l", str(BASE / "research.txt")],
            ["/usr/bin/sha256sum", str(BASE / "research.txt")],
        ],
    ),
]

assert len(WORKFLOWS) == 20

# ------------------------------------------------------------
# Log parser
# ------------------------------------------------------------

pattern = re.compile(
    r"PID=(\d+) \| UID=(\d+) \| PROCESS=(.*?) "
    r"\| PATH=(.*?) \| RISK=(.*?) "
    r"\| REASON=(.*?) \| ACTION=(.*)"
)

def parse_line(line):

    m = pattern.match(line.strip())

    if not m:
        return None

    pid, uid, process, path, risk, reason, action = m.groups()

    return {
        "pid": int(pid),
        "uid": int(uid),
        "process": process,
        "path": path,
        "risk": risk,
        "reason": reason,
        "action": action,
    }


def get_offset():

    with LOG.open("r", errors="replace") as f:
        return f.seek(0, os.SEEK_END)


def get_new_lines(offset):

    with LOG.open("r", errors="replace") as f:
        f.seek(offset)
        return f.readlines()


# ------------------------------------------------------------
# Generate dataset
# ------------------------------------------------------------

event_rows = []
run_rows = []

print()
print("=" * 70)
print(" KernelGuard — Composite Benign Dataset")
print("=" * 70)
print()
print("Workflow types :", len(WORKFLOWS))
print("Repetitions    : 20")
print("Total runs     :", len(WORKFLOWS) * 20)
print()

run_number = 0

for workflow_id, commands in WORKFLOWS:

    for repetition in range(1, 21):

        run_number += 1
        run_id = f"CB{run_number:04d}"

        start_offset = get_offset()
        start_time = time.time()

        for cmd in commands:

            try:
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
            except Exception:
                pass

        time.sleep(0.2)

        end_time = time.time()

        lines = get_new_lines(start_offset)

        parsed = []

        for line in lines:

            event = parse_line(line)

            if event is None:
                continue

            if event["path"] not in KNOWN_PATHS:
                continue

            event["run_id"] = run_id
            event["workflow_id"] = workflow_id
            event["repetition"] = repetition
            event["label"] = "benign"
            event["timestamp_start"] = start_time
            event["timestamp_end"] = end_time

            parsed.append(event)
            event_rows.append(event)

        run_rows.append({
            "run_id": run_id,
            "workflow_id": workflow_id,
            "repetition": repetition,
            "label": "benign",
            "event_count": len(parsed),
            "duration_sec": round(end_time - start_time, 4),
        })

        print(
            f"[{run_number:03d}/400] "
            f"{workflow_id:<28} "
            f"run={repetition:02d} "
            f"events={len(parsed)}"
        )

# ------------------------------------------------------------
# Save
# ------------------------------------------------------------

event_fields = [
    "run_id",
    "workflow_id",
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

run_fields = [
    "run_id",
    "workflow_id",
    "repetition",
    "label",
    "event_count",
    "duration_sec",
]

with META_FILE.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=run_fields)
    writer.writeheader()
    writer.writerows(run_rows)

print()
print("=" * 70)
print(" Composite dataset completed")
print("=" * 70)
print()
print("Total composite events:", len(event_rows))
print("Total composite runs  :", len(run_rows))
print()
print("Events:")
print(CSV_FILE)
print()
print("Metadata:")
print(META_FILE)
