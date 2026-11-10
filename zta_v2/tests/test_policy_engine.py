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
