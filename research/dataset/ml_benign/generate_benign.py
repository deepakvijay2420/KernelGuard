#!/usr/bin/env python3

import subprocess
import time
from pathlib import Path

TEST_DIR = Path("/tmp/kernelguard-ml-benign")

TEST_DIR.mkdir(
    exist_ok=True
)

(TEST_DIR / "research.txt").write_text(
    "KernelGuard benign ML training data\n"
)

commands = [
    ["/usr/bin/ls", "-la", str(TEST_DIR)],
    ["/usr/bin/cat", str(TEST_DIR / "research.txt")],
    ["/usr/bin/date"],
    ["/usr/bin/whoami"],
    ["/bin/pwd"],
    ["/usr/bin/grep", "KernelGuard", str(TEST_DIR / "research.txt")],
    ["/usr/bin/uname", "-a"],
]

print()
print("KernelGuard ML benign workload")
print("==============================")
print()

for round_no in range(20):

    print(
        f"[{round_no + 1}/20] "
        "Generating benign behaviour..."
    )

    for command in commands:

        try:

            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )

        except Exception:
            pass

        time.sleep(0.05)

print()
print("Benign workload completed.")
print()
