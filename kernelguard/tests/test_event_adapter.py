import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.event_adapter import EventSchemaError, normalize_bpf_event, normalize_bpf_events


class TestEventAdapter(unittest.TestCase):
    def setUp(self):
        self.event = {
            "ts_ns": 2_500_000_000, "cgroup_id": 77, "agent": 3,
            "hook": "exec", "verdict": "deny", "pid": 123,
            "comm": "bash", "name": "/usr/bin/bash", "ino": 99,
            "dev": 8, "dst": "", "port": 0, "family": 0
        }

    def test_maps_bpf_fields(self):
        row = normalize_bpf_event(self.event)
        self.assertEqual(row["process"], "bash")
        self.assertEqual(row["path"], "/usr/bin/bash")
        self.assertEqual(row["pid"], 123)
        self.assertEqual(row["agent"], 3)
        self.assertEqual(row["cgroup_id"], 77)
        self.assertEqual(row["timestamp_start"], 2.5)
        self.assertIsNone(row["uid"])

    def test_rejects_missing_fields(self):
        with self.assertRaises(EventSchemaError):
            normalize_bpf_event({"ts_ns": 1})

    def test_rejects_bad_integer(self):
        bad = dict(self.event, ts_ns="invalid")
        with self.assertRaises(EventSchemaError):
            normalize_bpf_event(bad)

    def test_sorts_by_monotonic_timestamp(self):
        rows = normalize_bpf_events([
            dict(self.event, ts_ns=20),
            dict(self.event, ts_ns=10),
        ])
        self.assertEqual([r["ts_ns"] for r in rows], [10, 20])


if __name__ == "__main__":
    unittest.main()
