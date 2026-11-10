#!/usr/bin/env python3
import os
import struct
import yaml
from pathlib import Path

POLICY = Path("policy/policy.yaml")
OUTPUT = Path("policy/policy.bin")
CGROUP = Path("/sys/fs/cgroup/kernelguard-research-agent")

policy = yaml.safe_load(POLICY.read_text())

if not CGROUP.exists():
    raise SystemExit("Research-agent cgroup does not exist")

current_id = str(CGROUP.stat().st_ino)
agents = policy.get("agents", {})

if current_id not in agents:
    raise SystemExit(
        f"Cgroup ID {current_id} is missing from policy.yaml"
    )

records = []

for cgroup_id, agent in agents.items():
    if str(cgroup_id) != current_id:
        raise SystemExit(
            f"Unexpected/stale cgroup ID: {cgroup_id}"
        )

    for filename in agent.get("allowed_executables", []):
        encoded = filename.encode()
        if len(encoded) >= 128:
            raise SystemExit(f"Filename too long: {filename}")
        records.append((int(cgroup_id), encoded, 1))

    for filename in agent.get("denied_executables", []):
        encoded = filename.encode()
        if len(encoded) >= 128:
            raise SystemExit(f"Filename too long: {filename}")
        records.append((int(cgroup_id), encoded, 2))

with OUTPUT.open("wb") as f:
    f.write(struct.pack("<I", len(records)))

    for cgroup_id, filename, decision in records:
        f.write(struct.pack(
            "<Q128sI",
            cgroup_id,
            filename,
            decision
        ))

print(f"[OK] Compiled {len(records)} policy entries")
print(f"[OK] Cgroup ID: {current_id}")
print(f"[OK] Output: {OUTPUT}")
