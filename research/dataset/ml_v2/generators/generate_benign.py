#!/usr/bin/env python3

import os
import subprocess
import time
import random
from pathlib import Path

LAB = Path("/tmp/kernelguard-ml-lab")

LAB.mkdir(parents=True, exist_ok=True)

# Create controlled research files
for i in range(1, 21):
    (LAB / f"research_{i:02d}.txt").write_text(
        f"KernelGuard research sample {i}\n"
        "This is a controlled benign dataset file.\n"
        "Agent behavioral analysis experiment.\n"
    )

for i in range(1, 11):
    (LAB / f"log_{i:02d}.log").write_text(
        "\n".join([
            "INFO research task started",
            "INFO reading controlled file",
            "INFO processing dataset",
            "INFO task completed",
        ])
    )

(LAB / "README.txt").write_text(
    "KernelGuard ML benign workload laboratory.\n"
)

(LAB / "numbers.txt").write_text(
    "\n".join(str(i) for i in range(1, 101))
)

(LAB / "words.txt").write_text(
    "\n".join([
        "kernel",
        "agent",
        "security",
        "linux",
        "ebpf",
        "policy",
        "agent",
        "kernel",
        "security",
        "runtime",
    ])
)

def run(cmd):
    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
    except Exception:
        pass

def task_01():
    run(["/bin/pwd"])
    run(["/bin/ls", "-la", str(LAB)])
    run(["/usr/bin/whoami"])

def task_02():
    run(["/bin/ls", str(LAB)])
    run(["/bin/cat", str(LAB / "README.txt")])
    run(["/usr/bin/wc", "-l", str(LAB / "README.txt")])

def task_03():
    run(["/usr/bin/head", "-n", "3", str(LAB / "numbers.txt")])
    run(["/usr/bin/tail", "-n", "3", str(LAB / "numbers.txt")])
    run(["/usr/bin/wc", "-l", str(LAB / "numbers.txt")])

def task_04():
    run(["/usr/bin/grep", "kernel", str(LAB / "words.txt")])
    run(["/usr/bin/grep", "security", str(LAB / "words.txt")])
    run(["/usr/bin/grep", "agent", str(LAB / "words.txt")])

def task_05():
    run(["/usr/bin/sort", str(LAB / "words.txt")])
    run(["/usr/bin/uniq", str(LAB / "words.txt")])
    run(["/usr/bin/wc", "-l", str(LAB / "words.txt")])

def task_06():
    run(["/usr/bin/cut", "-d", " ", "-f", "1", str(LAB / "README.txt")])
    run(["/usr/bin/tr", "a-z", "A-Z"])
    
def task_07():
    run(["/usr/bin/file", str(LAB / "README.txt")])
    run(["/usr/bin/stat", str(LAB / "README.txt")])
    run(["/usr/bin/du", "-h", str(LAB)])

def task_08():
    run(["/usr/bin/sha256sum", str(LAB / "README.txt")])
    run(["/usr/bin/sha256sum", str(LAB / "numbers.txt")])
    run(["/usr/bin/md5sum", str(LAB / "README.txt")])

def task_09():
    run(["/bin/echo", "KernelGuard benign task"])
    run(["/usr/bin/printf", "research\n"])
    run(["/bin/echo", "completed"])

def task_10():
    run(["/bin/mkdir", "-p", str(LAB / "workspace")])
    run(["/usr/bin/touch", str(LAB / "workspace" / "test.txt")])
    run(["/bin/ls", str(LAB / "workspace")])

def task_11():
    src = LAB / "README.txt"
    dst = LAB / "workspace" / "README_copy.txt"
    run(["/bin/cp", str(src), str(dst)])
    run(["/usr/bin/stat", str(dst)])
    run(["/bin/rm", "-f", str(dst)])

def task_12():
    src = LAB / "research_01.txt"
    dst = LAB / "workspace" / "research_moved.txt"
    run(["/bin/cp", str(src), str(dst)])
    run(["/bin/mv", str(dst), str(LAB / "research_moved.txt")])
    run(["/bin/rm", "-f", str(LAB / "research_moved.txt")])

def task_13():
    run(["/usr/bin/uname", "-a"])
    run(["/bin/hostname"])
    run(["/bin/date"])

def task_14():
    run(["/usr/bin/uptime"])
    run(["/usr/bin/free", "-h"])
    run(["/bin/df", "-h", str(LAB)])

def task_15():
    run(["/usr/bin/id"])
    run(["/usr/bin/whoami"])
    run(["/bin/pwd"])

def task_16():
    run(["/usr/bin/find", str(LAB), "-maxdepth", "1", "-type", "f"])
    run(["/usr/bin/find", str(LAB), "-maxdepth", "1", "-type", "d"])

def task_17():
    run(["/usr/bin/grep", "INFO", str(LAB / "log_01.log")])
    run(["/usr/bin/sort", str(LAB / "log_01.log")])
    run(["/usr/bin/wc", "-l", str(LAB / "log_01.log")])

def task_18():
    run(["/bin/cat", str(LAB / "log_02.log")])
    run(["/usr/bin/head", "-n", "2", str(LAB / "log_02.log")])
    run(["/usr/bin/tail", "-n", "2", str(LAB / "log_02.log")])

def task_19():
    run(["/usr/bin/awk", "{print $1}", str(LAB / "log_03.log")])
    run(["/usr/bin/grep", "research", str(LAB / "log_03.log")])

def task_20():
    run(["/usr/bin/sed", "-n", "1,3p", str(LAB / "log_04.log")])
    run(["/usr/bin/wc", "-w", str(LAB / "log_04.log")])

def task_21():
    run(["/bin/ls", "-lah", str(LAB)])
    run(["/usr/bin/du", "-sh", str(LAB)])
    run(["/usr/bin/stat", str(LAB)])

def task_22():
    run(["/usr/bin/cat", str(LAB / "research_05.txt")])
    run(["/usr/bin/sha256sum", str(LAB / "research_05.txt")])
    run(["/usr/bin/stat", str(LAB / "research_05.txt")])

def task_23():
    run(["/usr/bin/head", "-n", "5", str(LAB / "research_06.txt")])
    run(["/usr/bin/grep", "controlled", str(LAB / "research_06.txt")])
    run(["/usr/bin/wc", "-c", str(LAB / "research_06.txt")])

def task_24():
    run(["/usr/bin/find", str(LAB), "-name", "*.txt"])
    run(["/usr/bin/find", str(LAB), "-name", "*.log"])

def task_25():
    run(["/bin/ls", str(LAB)])
    run(["/usr/bin/file", str(LAB / "research_10.txt")])
    run(["/usr/bin/stat", str(LAB / "research_10.txt")])

def task_26():
    run(["/bin/echo", "dataset"])
    run(["/bin/echo", "feature"])
    run(["/bin/echo", "behavior"])
    run(["/bin/echo", "analysis"])

def task_27():
    run(["/bin/cat", str(LAB / "words.txt")])
    run(["/usr/bin/sort", str(LAB / "words.txt")])
    run(["/usr/bin/uniq", str(LAB / "words.txt")])

def task_28():
    run(["/usr/bin/wc", "-l", str(LAB / "research_11.txt")])
    run(["/usr/bin/wc", "-c", str(LAB / "research_11.txt")])
    run(["/usr/bin/wc", "-w", str(LAB / "research_11.txt")])

def task_29():
    run(["/usr/bin/sha256sum", str(LAB / "research_12.txt")])
    run(["/usr/bin/md5sum", str(LAB / "research_12.txt")])
    run(["/usr/bin/file", str(LAB / "research_12.txt")])

def task_30():
    run(["/usr/bin/hostname"])
    run(["/usr/bin/uname", "-r"])
    run(["/usr/bin/uptime"])

def task_31():
    run(["/bin/ls", "-l", str(LAB)])
    run(["/bin/ls", "-lh", str(LAB)])
    run(["/bin/ls", "-a", str(LAB)])

def task_32():
    run(["/usr/bin/grep", "KernelGuard", str(LAB / "README.txt")])
    run(["/usr/bin/grep", "benign", str(LAB / "README.txt")])
    run(["/usr/bin/grep", "laboratory", str(LAB / "README.txt")])

def task_33():
    run(["/usr/bin/find", str(LAB), "-type", "f"])
    run(["/usr/bin/find", str(LAB), "-type", "f", "-name", "*.txt"])

def task_34():
    run(["/bin/mkdir", "-p", str(LAB / "reports")])
    run(["/bin/echo", "report generated"])
    run(["/usr/bin/touch", str(LAB / "reports" / "report.txt")])
    run(["/bin/ls", str(LAB / "reports")])

def task_35():
    run(["/bin/cp", str(LAB / "README.txt"), str(LAB / "reports" / "summary.txt")])
    run(["/usr/bin/sha256sum", str(LAB / "reports" / "summary.txt")])
    run(["/bin/rm", "-f", str(LAB / "reports" / "summary.txt")])

def task_36():
    run(["/usr/bin/head", "-n", "10", str(LAB / "numbers.txt")])
    run(["/usr/bin/tail", "-n", "10", str(LAB / "numbers.txt")])
    run(["/usr/bin/sort", str(LAB / "numbers.txt")])

def task_37():
    run(["/usr/bin/grep", "INFO", str(LAB / "log_05.log")])
    run(["/usr/bin/grep", "completed", str(LAB / "log_05.log")])
    run(["/usr/bin/wc", "-l", str(LAB / "log_05.log")])

def task_38():
    run(["/bin/true"])
    run(["/bin/echo", "task"])
    run(["/bin/false"])

def task_39():
    run(["/usr/bin/stat", str(LAB / "research_15.txt")])
    run(["/usr/bin/file", str(LAB / "research_15.txt")])
    run(["/usr/bin/du", "-h", str(LAB / "research_15.txt")])

def task_40():
    run(["/bin/pwd"])
    run(["/usr/bin/find", str(LAB), "-maxdepth", "1"])
    run(["/bin/ls", "-lah", str(LAB)])

TASKS = [
    task_01, task_02, task_03, task_04, task_05,
    task_06, task_07, task_08, task_09, task_10,
    task_11, task_12, task_13, task_14, task_15,
    task_16, task_17, task_18, task_19, task_20,
    task_21, task_22, task_23, task_24, task_25,
    task_26, task_27, task_28, task_29, task_30,
    task_31, task_32, task_33, task_34, task_35,
    task_36, task_37, task_38, task_39, task_40
]

REPETITIONS = 10

print("=" * 60)
print(" KernelGuard ML V2 - Benign Dataset Generator")
print("=" * 60)
print(f"Task types : {len(TASKS)}")
print(f"Repetitions: {REPETITIONS}")
print(f"Expected workloads: {len(TASKS) * REPETITIONS}")
print(f"Lab        : {LAB}")
print()

random.seed(42)

for repetition in range(1, REPETITIONS + 1):

    order = list(range(len(TASKS)))
    random.shuffle(order)

    print(f"[+] Repetition {repetition}/{REPETITIONS}")

    for position, index in enumerate(order, 1):
        TASKS[index]()
        time.sleep(random.uniform(0.08, 0.20))

    print(f"    completed {len(TASKS)} task patterns")

print()
print("=" * 60)
print(" Benign dataset generation completed")
print("=" * 60)
