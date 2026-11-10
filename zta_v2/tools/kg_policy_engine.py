#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

import yaml


VALID_DECISIONS = {"ALLOW", "DENY", "REVIEW"}


def load_policy(path):
    with open(path, "r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle)

    if not isinstance(policy, dict):
        raise ValueError("Policy must be a YAML mapping")

    default = policy.get("default_decision", "REVIEW")

    if default not in VALID_DECISIONS:
        raise ValueError("Invalid default_decision")

    agents = policy.get("agents", {})

    if not isinstance(agents, dict):
        raise ValueError("'agents' must be a YAML mapping")

    for cgroup_id, agent in agents.items():
        if not isinstance(agent, dict):
            raise ValueError(f"Invalid agent entry: {cgroup_id}")

        for field in ("allowed_executables", "denied_executables"):
            values = agent.get(field, [])

            if not isinstance(values, list):
                raise ValueError(f"{field} must be a list")

            if not all(isinstance(value, str) for value in values):
                raise ValueError(f"{field} must contain strings")

    return policy


def evaluate_event(event, policy):
    required = ("tgid", "uid", "cgroup_id", "comm", "filename")

    for field in required:
        if field not in event:
            raise ValueError(f"Event missing field: {field}")

    cgroup_id = str(event["cgroup_id"])
    filename = event["filename"]

    agent = policy.get("agents", {}).get(cgroup_id)

    if agent is None:
        return {
            "decision": policy.get("default_decision", "REVIEW"),
            "reason": "Unknown cgroup identity",
            "agent": "unknown",
        }

    allowed = agent.get("allowed_executables", [])
    denied = agent.get("denied_executables", [])

    if filename in denied:
        decision = "DENY"
        reason = "Executable explicitly denied by policy"

    elif filename in allowed:
        decision = "ALLOW"
        reason = "Executable explicitly allowed by policy"

    else:
        decision = "REVIEW"
        reason = "Executable not present in allow or deny lists"

    return {
        "decision": decision,
        "reason": reason,
        "agent": agent.get("name", "unnamed"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="KernelGuard v2 Zero Trust policy evaluator"
    )

    parser.add_argument(
        "--policy",
        default="policy/policy.yaml",
        help="Path to YAML policy",
    )

    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
    except Exception as exc:
        print(f"[POLICY ERROR] {exc}", file=sys.stderr)
        return 1

    print("[KernelGuard ZTA] Policy engine started.", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)

            result = evaluate_event(event, policy)

            output = {
                "event": event.get("event", "UNKNOWN"),
                "tgid": event["tgid"],
                "uid": event["uid"],
                "cgroup_id": event["cgroup_id"],
                "comm": event["comm"],
                "filename": event["filename"],
                "agent": result["agent"],
                "decision": result["decision"],
                "reason": result["reason"],
            }

            print(json.dumps(output), flush=True)

        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            print(
                json.dumps({
                    "decision": "REVIEW",
                    "reason": f"Invalid event: {exc}",
                }),
                flush=True,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
