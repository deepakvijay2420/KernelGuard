"""Tests for the shipped policy, the linter and the pin tool.  No root, no BPF."""
import copy
import os
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import kgctl            # noqa: E402
import policy_lint as L  # noqa: E402
import policy_pin as P   # noqa: E402

POLICY = os.path.join(ROOT, "policy", "policy.hardened.yaml")
CAT = yaml.safe_load(open(os.path.join(ROOT, "policy", "dangerous_commands.yaml")))["categories"]


def load():
    return yaml.safe_load(open(POLICY))


class Shipped(unittest.TestCase):
    def test_validates(self):
        kgctl.validate_policy(load())

    def test_lints_clean(self):
        fails, _ = L.lint(load(), CAT)
        self.assertEqual(fails, [])

    def test_sensitive_names(self):
        s = load()["sensitive"]
        names = s["taint"] + s["deny"]
        self.assertEqual(len(names), len(set(names)), "duplicate sensitive names")
        self.assertLess(len(names), 256, "sensitive_names map holds 256 entries")
        self.assertTrue(all(len(n.encode()) <= 31 and "/" not in n for n in names))
        self.assertNotIn("passwd", names, "NSS needs /etc/passwd")

    def test_least_privilege_shape(self):
        pol = load()
        ids = [a["id"] for a in pol["agents"].values()]
        self.assertEqual(len(ids), len(set(ids)))
        for name, a in pol["agents"].items():
            self.assertIn("/usr/bin/python3", a["exec"]["allow"], name)
            self.assertEqual(a["network"]["egress_default"], "deny", name)
            self.assertEqual(a["mode"], "audit", "ship in audit; promote after a clean run")
        self.assertEqual(pol["agents"]["airgapped_agent"]["network"]["allow"], [])
        # research must be a strict subset of coding: coding adds tools, never removes any
        r = set(pol["agents"]["research_agent"]["exec"]["allow"])
        c = set(pol["agents"]["coding_agent"]["exec"]["allow"])
        self.assertTrue(r - {"/usr/bin/uname"} <= c)

    def test_catalog_names_never_allowed(self):
        bad = {n for v in CAT.values() for n in v["names"]}
        for name, a in load()["agents"].items():
            for e in a["exec"]["allow"]:
                self.assertNotIn(os.path.basename(e), bad, f"{name}: {e}")


class LintRules(unittest.TestCase):
    def mutate(self, fn):
        pol = copy.deepcopy(load())
        fn(pol["agents"]["research_agent"])
        return L.lint(pol, CAT)

    def test_dangerous_command_fails(self):
        f, _ = self.mutate(lambda a: a["exec"]["allow"].append("/usr/bin/curl"))
        self.assertTrue(any("curl" in x for x in f))

    def test_relative_path_fails(self):
        f, _ = self.mutate(lambda a: a["exec"]["allow"].append("bin/tool"))
        self.assertTrue(any("not absolute" in x for x in f))

    def test_open_egress_fails_unless_allowed(self):
        f, _ = self.mutate(lambda a: a["network"].update(egress_default="allow"))
        self.assertTrue(any("egress_default" in x for x in f))
        pol = copy.deepcopy(load())
        pol["agents"]["research_agent"]["network"]["egress_default"] = "allow"
        f2, _ = L.lint(pol, CAT, allow_open_egress=True)
        self.assertFalse(any("egress_default" in x for x in f2))

    def test_any_port_external_fails_but_loopback_ok(self):
        f, _ = self.mutate(lambda a: a["network"]["allow"].append({"ip": "8.8.8.8", "port": 0}))
        self.assertTrue(any("ANY port" in x for x in f))
        f, _ = self.mutate(lambda a: a["network"]["allow"].append({"ip": "127.0.0.1", "port": 0}))
        self.assertFalse(any("ANY port" in x for x in f))

    def test_agent_writable_binary_fails(self):
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "tool")
            open(exe, "w").write("#!/bin/sh\n")
            os.chmod(exe, 0o777)
            f, _ = self.mutate(lambda a: a["exec"]["allow"].append(exe))
            self.assertTrue(any("replace it" in x for x in f), f)

    def test_missing_mode_and_empty_allow_fail(self):
        f, _ = self.mutate(lambda a: a.pop("mode"))
        self.assertTrue(any("mode must be" in x for x in f))
        f, _ = self.mutate(lambda a: a["exec"].update(allow=[]))
        self.assertTrue(any("empty" in x for x in f))

    def test_strict_turns_warnings_into_failures(self):
        f, w = L.lint(load(), CAT, strict=True)
        self.assertTrue(f and not w)
        self.assertTrue(all(x.startswith("(strict)") for x in f))

    def test_unpinned_warning_is_aggregated(self):
        _, w = L.lint(load(), CAT)
        self.assertEqual(sum("not pinned" in x for x in w), 3)     # one line per agent


class Pin(unittest.TestCase):
    TEXT = ("sensitive:\n  deny: [shadow]\nagents:\n  a:\n    id: 1\n    mode: audit\n"
            "    workdir: /var/lib/x   # keep\n    exec:\n      allow:\n        - /usr/bin/ls   # list\n"
            "        - /usr/bin/cat\n    network:\n      allow:\n        - {ip: 127.0.0.1, port: 0}\n")

    def test_pins_only_exec_allow_and_keeps_comments(self):
        out = P.pin(self.TEXT)
        self.assertEqual(out.count("sha256"), 2)
        self.assertIn("# list", out)
        self.assertIn("workdir: /var/lib/x   # keep", out)
        self.assertIn("{ip: 127.0.0.1, port: 0}", out)
        data = yaml.safe_load(out)
        ls = data["agents"]["a"]["exec"]["allow"][0]
        self.assertEqual(ls["path"], "/usr/bin/ls")
        self.assertEqual(ls["sha256"], P.sha(os.path.realpath("/usr/bin/ls")))

    def test_pinned_policy_round_trips_through_lint_without_unpinned_warning(self):
        pol = yaml.safe_load(P.pin(open(POLICY).read()))
        kgctl.validate_policy(pol)
        _, w = L.lint(pol, CAT)
        self.assertFalse(any("not pinned" in x for x in w))

    def test_nothing_to_pin_is_an_error(self):
        with self.assertRaises(SystemExit):
            P.pin("version: 1\nagents: {}\n")

    def test_missing_binary_is_an_error(self):
        with self.assertRaises(SystemExit):
            P.pin("agents:\n  a:\n    exec:\n      allow:\n        - /nonexistent/zzz\n")


if __name__ == "__main__":
    unittest.main()
