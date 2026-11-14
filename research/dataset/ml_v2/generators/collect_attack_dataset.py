#!/usr/bin/env python3

import csv
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

BASE = Path("/tmp/kernelguard-ml-lab")
LOG = Path.home() / "kernelguard/logs/kernelguard_live.log"

OUT_DIR = Path.home() / "kernelguard/dataset/ml_v2/attacks"
EVENT_FILE = OUT_DIR / "attack_events.csv"
RUN_FILE = OUT_DIR / "attack_runs.csv"

BASE.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------
# Controlled files
# ------------------------------------------------------------

(BASE / "README.txt").write_text(
    "KernelGuard controlled attack dataset\n"
    "This file is harmless test data.\n"
)

(BASE / "research.txt").write_text(
    "KernelGuard\n"
    "Agentic AI\n"
    "eBPF\n"
    "Zero Trust\n"
)

# ------------------------------------------------------------
# Safe /tmp executable
#
# This is simply a copy of /bin/echo.
# Executing it is harmless, but it gives us a
# suspicious /tmp executable path.
# ------------------------------------------------------------

TMP_EXEC = Path("/tmp/kernelguard-attack-test")

try:
    shutil.copy2("/bin/echo", TMP_EXEC)
    TMP_EXEC.chmod(0o755)
except Exception as exc:
    print("[!] Could not create /tmp executable:", exc)

# Unknown executable: harmless copy of /bin/true
UNKNOWN_EXEC = Path("/tmp/kernelguard_unknown_exec")

try:
    shutil.copy2("/bin/true", UNKNOWN_EXEC)
    UNKNOWN_EXEC.chmod(0o755)
except Exception as exc:
    print("[!] Could not create unknown executable:", exc)

# ------------------------------------------------------------
# Commands that may legitimately appear
# ------------------------------------------------------------

KNOWN_PATHS = {
    "/bin/ls",
    "/bin/cat",
    "/bin/bash",
    "/bin/sh",
    "/bin/echo",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/grep",
    "/usr/bin/wc",
    "/usr/bin/stat",
    "/usr/bin/sha256sum",
    "/usr/bin/true",
    "/usr/bin/id",
    "/usr/bin/date",
    "/usr/bin/pwd",
    "/usr/bin/uname",
    "/usr/bin/find",
    "/usr/bin/rm",
    "/usr/bin/cp",
    "/usr/bin/mv",
    "/usr/bin/touch",
}

# ------------------------------------------------------------
# Attack-like behavioral workflows
#
# Every command is harmless.
# The security scenario is represented by the sequence.
# ------------------------------------------------------------

ATTACKS = [

    (
        "prompt_injection_sudo",
        [
            ["/bin/ls", str(BASE)],
            ["/bin/cat", str(BASE / "README.txt")],
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/echo",
                "KERNELGUARD_PROMPT_INJECTION_TEST",
            ],
        ],
    ),

    (
        "prompt_injection_bash",
        [
            ["/bin/ls", str(BASE)],
            ["/bin/cat", str(BASE / "research.txt")],
            [
                "/bin/bash",
                "-c",
                "echo KERNELGUARD_ATTACK_TEST",
            ],
        ],
    ),

    (
        "shell_execution_chain",
        [
            ["/bin/ls", str(BASE)],
            [
                "/bin/bash",
                "-c",
                "/bin/sh -c 'echo KERNELGUARD_SHELL_TEST'",
            ],
        ],
    ),

    (
        "password_utility",
        [
            ["/bin/ls", str(BASE)],
            [
                "/usr/bin/passwd",
                "--help",
            ],
        ],
    ),

    (
        "tmp_executable",
        [
            ["/bin/ls", str(BASE)],
            [str(TMP_EXEC), "KERNELGUARD_TMP_TEST"],
        ],
    ),

    (
        "unknown_executable",
        [
            ["/bin/ls", str(BASE)],
            [str(UNKNOWN_EXEC)],
        ],
    ),

    (
        "benign_to_sudo",
        [
            ["/bin/pwd"],
            ["/bin/ls", str(BASE)],
            ["/bin/cat", str(BASE / "README.txt")],
            [
                "/usr/bin/grep",
                "KernelGuard",
                str(BASE / "README.txt"),
            ],
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/echo",
                "KERNELGUARD_SENSITIVE_TEST",
            ],
        ],
    ),

    (
        "benign_to_shell",
        [
            ["/usr/bin/id"],
            ["/usr/bin/date"],
            ["/bin/cat", str(BASE / "research.txt")],
            [
                "/bin/bash",
                "-c",
                "echo KERNELGUARD_SHELL_TEST",
            ],
        ],
    ),

    (
        "repeated_sudo",
        [
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/echo",
                "KG_TEST_1",
            ],
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/echo",
                "KG_TEST_2",
            ],
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/echo",
                "KG_TEST_3",
            ],
        ],
    ),

    (
        "repeated_shell",
        [
            [
                "/bin/bash",
                "-c",
                "echo KG_BASH_1",
            ],
            [
                "/bin/sh",
                "-c",
                "echo KG_SH_2",
            ],
            [
                "/bin/bash",
                "-c",
                "echo KG_BASH_3",
            ],
        ],
    ),
]

assert len(ATTACKS) == 10

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
# Generate attack dataset
# ------------------------------------------------------------

event_rows = []
run_rows = []

REPETITIONS = 30

print()
print("=" * 70)
print(" KernelGuard — Controlled Attack Dataset")
print("=" * 70)
print()
print("Attack types :", len(ATTACKS))
print("Repetitions  :", REPETITIONS)
print("Total runs   :", len(ATTACKS) * REPETITIONS)
print()
print("IMPORTANT: all commands are harmless controlled tests.")
print()

run_number = 0

for attack_id, commands in ATTACKS:

    for repetition in range(1, REPETITIONS + 1):

        run_number += 1
        run_id = f"AT{run_number:04d}"

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

            # Keep only events belonging to this controlled
            # attack vocabulary.
            if (
                event["path"] not in KNOWN_PATHS
                and not event["path"].startswith("/tmp/kernelguard")
            ):
                continue

            event["run_id"] = run_id
            event["attack_id"] = attack_id
            event["repetition"] = repetition
            event["label"] = "attack"
            event["timestamp_start"] = start_time
            event["timestamp_end"] = end_time

            parsed.append(event)
            event_rows.append(event)

        run_rows.append({
            "run_id": run_id,
            "attack_id": attack_id,
            "repetition": repetition,
            "label": "attack",
            "event_count": len(parsed),
            "duration_sec": round(
                end_time - start_time,
                4
            ),
        })

        print(
            f"[{run_number:03d}/300] "
            f"{attack_id:<28} "
            f"run={repetition:02d} "
            f"events={len(parsed)}"
        )

# ------------------------------------------------------------
# Save event dataset
# ------------------------------------------------------------

event_fields = [
    "run_id",
    "attack_id",
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

with EVENT_FILE.open("w", newline="") as f:

    writer = csv.DictWriter(
        f,
        fieldnames=event_fields
    )

    writer.writeheader()
    writer.writerows(event_rows)

# ------------------------------------------------------------
# Save run metadata
# ------------------------------------------------------------

run_fields = [
    "run_id",
    "attack_id",
    "repetition",
    "label",
    "event_count",
    "duration_sec",
]

with RUN_FILE.open("w", newline="") as f:

    writer = csv.DictWriter(
        f,
        fieldnames=run_fields
    )

    writer.writeheader()
    writer.writerows(run_rows)

print()
print("=" * 70)
print(" Attack dataset completed")
print("=" * 70)
print()
print("Total attack events:", len(event_rows))
print("Total attack runs  :", len(run_rows))
print()
print("Events:")
print(EVENT_FILE)
print()
print("Metadata:")
print(RUN_FILE)
