#!/usr/bin/env bash
set -Eeuo pipefail

cd "$HOME/kernelguard"
V2="$HOME/kernelguard/zta_v2"

echo "======================================"
echo " KERNELGUARD V2 POLICY ENGINE SETUP"
echo "======================================"

# Check PyYAML
if ! python3 -c "import yaml" >/dev/null 2>&1; then
    echo "[INFO] Installing Python YAML support..."
    sudo apt-get update
    sudo apt-get install -y python3-yaml
fi

mkdir -p "$V2/policy" "$V2/tests" "$V2/tools"

# 1. YAML policy
cat > "$V2/policy/policy.yaml" <<'YAML'
version: 1

# Unknown processes are never automatically trusted.
default_decision: REVIEW

agents:
  # Replace this placeholder with the actual cgroup ID
  # of your isolated AI agent process.
  "REPLACE_WITH_AGENT_CGROUP_ID":
    name: research_agent

    allowed_executables:
      - /usr/bin/python3
      - /usr/bin/ls

    denied_executables:
      - /usr/bin/sudo

    # Any executable not explicitly allowed or denied
    # receives REVIEW.
YAML

# 2. Policy engine
cat > "$V2/tools/kg_policy_engine.py" <<'PYTHON'
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
PYTHON

chmod +x "$V2/tools/kg_policy_engine.py"

# 3. Automated tests
cat > "$V2/tests/test_policy_engine.py" <<'PYTHON'
import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "tools")
)

from kg_policy_engine import evaluate_event


POLICY = {
    "default_decision": "REVIEW",
    "agents": {
        "12345": {
            "name": "research_agent",
            "allowed_executables": [
                "/usr/bin/python3",
                "/usr/bin/ls",
            ],
            "denied_executables": [
                "/usr/bin/sudo",
            ],
        }
    },
}


def make_event(filename, cgroup_id=12345):
    return {
        "event": "EXEC",
        "tgid": 1000,
        "uid": 1000,
        "cgroup_id": cgroup_id,
        "comm": "python3",
        "filename": filename,
    }


class PolicyEngineTests(unittest.TestCase):

    def test_allowed_executable(self):
        result = evaluate_event(
            make_event("/usr/bin/python3"), POLICY
        )
        self.assertEqual(result["decision"], "ALLOW")

    def test_denied_executable(self):
        result = evaluate_event(
            make_event("/usr/bin/sudo"), POLICY
        )
        self.assertEqual(result["decision"], "DENY")

    def test_unknown_executable(self):
        result = evaluate_event(
            make_event("/usr/bin/curl"), POLICY
        )
        self.assertEqual(result["decision"], "REVIEW")

    def test_unknown_cgroup(self):
        result = evaluate_event(
            make_event("/usr/bin/python3", 99999), POLICY
        )
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["agent"], "unknown")

    def test_agent_identity(self):
        result = evaluate_event(
            make_event("/usr/bin/python3"), POLICY
        )
        self.assertEqual(result["agent"], "research_agent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
PYTHON

echo
echo "========== RUNNING POLICY TESTS =========="

cd "$V2"
python3 -m unittest discover -s tests -v

echo
echo "========== POLICY FILE =========="
cat policy/policy.yaml

echo
echo "========== SETUP COMPLETE =========="
