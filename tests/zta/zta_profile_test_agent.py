#!/usr/bin/env python3
"""Interactive child-process test agent for KernelGuard ZTA.

Run this script, register its PID with zta_controller, then enter:
  allow  -> executes /usr/bin/ls
  deny   -> attempts /bin/bash (research_agent should be denied)
  exit   -> stops the test agent
"""
import os
import subprocess

print(f"TEST_AGENT_PID={os.getpid()}", flush=True)
print("Commands: allow | deny | exit", flush=True)

while True:
    try:
        command = input("agent> ").strip().lower()
    except EOFError:
        break

    if command == "allow":
        result = subprocess.run(["/usr/bin/ls", "/tmp"], check=False)
        print(f"ALLOW_TEST_RETURN_CODE={result.returncode}", flush=True)
    elif command == "deny":
        result = subprocess.run(
            ["/bin/bash", "-c", "echo BASH_EXECUTED"],
            check=False,
        )
        print(f"DENY_TEST_RETURN_CODE={result.returncode}", flush=True)
    elif command == "exit":
        break
    else:
        print("Unknown command", flush=True)
