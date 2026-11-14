"""
Unit tests for the unified KernelGuard controller. They need no root, no BPF attachment and no network:

    cd kernelguard && make test        (or: python3 -m unittest discover -s tests -v)

The layout test compiles bpf/kg_common.h with gcc and compares sizeof() with the
struct.pack() layouts, so Python and C can never silently drift apart.
"""
import hashlib
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import kgctl  # noqa: E402


def base_policy(**agent_over):
    agent = {"id": 1, "mode": "enforce", "exec": {"allow": ["/bin/ls"]}}
    agent.update(agent_over)
    return {"version": 1, "agents": {"a1": agent}}


class TestLayout(unittest.TestCase):
    def test_python_layouts_match_c_header(self):
        if not shutil.which("gcc"):
            self.skipTest("gcc not available")
        src = textwrap.dedent("""
            #include <stdio.h>
            #include <stddef.h>
            #include <linux/types.h>
            #include "kg_common.h"
            int main(void) {
                printf("%zu %zu %zu %zu %zu\\n",
                       sizeof(struct kg_agent_cfg), sizeof(struct kg_inode_key),
                       sizeof(struct kg_egress_key), sizeof(struct kg_name_key),
                       sizeof(struct kg_state));
                return 0;
            }
        """)
        with tempfile.TemporaryDirectory() as d:
            c = Path(d) / "t.c"
            c.write_text(src)
            exe = Path(d) / "t"
            subprocess.run(["gcc", "-Wall", "-I", str(ROOT / "bpf"), str(c), "-o", str(exe)], check=True)
            sizes = list(map(int, subprocess.run([str(exe)], capture_output=True, text=True,
                                                 check=True).stdout.split()))
        self.assertEqual(sizes[0], len(kgctl.pack_agent_cfg(1, 1, 1)))
        self.assertEqual(sizes[1], len(kgctl.pack_inode_key(1, 2, 3)))
        self.assertEqual(sizes[2], len(kgctl.pack_egress_key(1, "1.2.3.4", 443)))
        self.assertEqual(sizes[3], len(kgctl.pack_name_key("x")))
        self.assertEqual(sizes[4], 16)  # struct kg_state, only read by the kernel side


class TestPacking(unittest.TestCase):
    def test_kdev_encoding(self):
        self.assertEqual(kgctl.kdev(os.makedev(8, 1)), (8 << 20) | 1)
        self.assertEqual(kgctl.kdev(os.makedev(259, 3)), (259 << 20) | 3)

    def test_inode_key_fields(self):
        k = kgctl.pack_inode_key(0x1122334455667788, 0xAABBCCDD, 7)
        self.assertEqual(struct.unpack("<QII", k), (0x1122334455667788, 0xAABBCCDD, 7))

    def test_egress_key_address_is_network_order_and_port_host_order(self):
        k = kgctl.pack_egress_key(5, "10.1.2.3", 443)
        self.assertEqual(k[4:8], bytes([10, 1, 2, 3]))                 # network order
        self.assertEqual(struct.unpack("<HH", k[8:12]), (443, 0))     # host order, pad 0
        self.assertEqual(struct.unpack("<I", k[:4])[0], 5)

    def test_name_key_padding_and_truncation(self):
        self.assertEqual(kgctl.pack_name_key(".env"), b".env" + b"\0" * 28)
        long = "x" * 100
        k = kgctl.pack_name_key(long)
        self.assertEqual(len(k), 32)
        self.assertEqual(k[-1:], b"\0")          # always NUL terminated
        self.assertEqual(k[:31], b"x" * 31)

    def test_hex_helper(self):
        self.assertEqual(kgctl._hex(b"\x00\x0f\xff"), ["00", "0f", "ff"])


class TestValidation(unittest.TestCase):
    def assertRejects(self, pol, fragment):
        with self.assertRaises(kgctl.PolicyError) as cm:
            kgctl.validate_policy(pol)
        self.assertIn(fragment, str(cm.exception))

    def test_valid_policy_passes(self):
        kgctl.validate_policy(base_policy())

    def test_not_a_mapping(self):
        self.assertRejects([], "mapping")

    def test_wrong_version(self):
        p = base_policy()
        p["version"] = 2
        self.assertRejects(p, "version")

    def test_mode_is_mandatory(self):
        p = base_policy()
        del p["agents"]["a1"]["mode"]
        self.assertRejects(p, "mode")

    def test_bad_mode(self):
        self.assertRejects(base_policy(mode="yolo"), "mode")

    def test_id_range_and_uniqueness(self):
        self.assertRejects(base_policy(id=0), "id")
        self.assertRejects(base_policy(id=64), "id")
        p = base_policy()
        p["agents"]["a2"] = dict(p["agents"]["a1"])
        self.assertRejects(p, "already used")

    def test_exec_allow_must_be_nonempty(self):
        self.assertRejects(base_policy(exec={"allow": []}), "exec.allow")

    def test_bad_egress_default(self):
        self.assertRejects(base_policy(network={"egress_default": "maybe"}), "egress_default")

    def test_network_entry_needs_ip_xor_host(self):
        self.assertRejects(base_policy(network={"allow": [{"port": 1}]}), "ip")
        self.assertRejects(base_policy(network={"allow": [{"ip": "1.1.1.1", "host": "x", "port": 1}]}), "ip")

    def test_network_entry_needs_port(self):
        self.assertRejects(base_policy(network={"allow": [{"ip": "1.1.1.1"}]}), "port")

    def test_sensitive_name_rules(self):
        p = base_policy()
        p["sensitive"] = {"taint": ["a/b"]}
        self.assertRejects(p, "plain file name")
        p["sensitive"] = {"taint": ["x"], "deny": ["x"]}
        self.assertRejects(p, "both taint and deny")
        p["sensitive"] = {"deny": ["y" * 40]}
        self.assertRejects(p, "longer")

    def test_limits_must_be_positive_ints(self):
        self.assertRejects(base_policy(limits={"pids_max": 0}), "pids_max")


class TestPlan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.exe = self.dir / "tool"
        self.exe.write_bytes(b"#!/bin/true\n")
        self.exe.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def keys(self, plan, m):
        return {k for k, _ in plan["maps"][m]}

    def test_exec_is_identified_by_inode_of_the_real_file(self):
        st = os.stat(self.exe)
        plan = kgctl.build_plan(base_policy(exec={"allow": [str(self.exe)]}))
        want = kgctl.pack_inode_key(st.st_ino, kgctl.kdev(st.st_dev), 1)
        self.assertEqual(self.keys(plan, "exec_allow"), {want})

    def test_symlink_resolves_to_same_inode_but_copy_does_not(self):
        link = self.dir / "link"
        link.symlink_to(self.exe)
        copy = self.dir / "copy"
        shutil.copy(self.exe, copy)
        copy.chmod(0o755)

        p_link = kgctl.build_plan(base_policy(exec={"allow": [str(link)]}))
        p_real = kgctl.build_plan(base_policy(exec={"allow": [str(self.exe)]}))
        p_copy = kgctl.build_plan(base_policy(exec={"allow": [str(copy)]}))
        self.assertEqual(self.keys(p_link, "exec_allow"), self.keys(p_real, "exec_allow"))
        self.assertNotEqual(self.keys(p_copy, "exec_allow"), self.keys(p_real, "exec_allow"))

    def test_exec_keys_are_scoped_per_agent(self):
        p = base_policy(exec={"allow": [str(self.exe)]})
        p["agents"]["a2"] = {"id": 2, "mode": "audit", "exec": {"allow": []}}
        with self.assertRaises(kgctl.PolicyError):          # empty allow list rejected
            kgctl.build_plan(p)
        p["agents"]["a2"]["exec"] = {"allow": [str(self.exe)]}
        keys = self.keys(kgctl.build_plan(p), "exec_allow")
        self.assertEqual(len(keys), 2)                      # same binary, two agent ids

    def test_missing_or_non_executable_binary_is_an_error(self):
        with self.assertRaises(kgctl.PolicyError):
            kgctl.build_plan(base_policy(exec={"allow": [str(self.dir / "nope")]}))
        data = self.dir / "data.txt"
        data.write_text("x")
        with self.assertRaises(kgctl.PolicyError):
            kgctl.build_plan(base_policy(exec={"allow": [str(data)]}))
        with self.assertRaises(kgctl.PolicyError):
            kgctl.build_plan(base_policy(exec={"allow": ["/"]}))

    def test_sha256_pin(self):
        good = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        kgctl.build_plan(base_policy(exec={"allow": [{"path": str(self.exe), "sha256": good}]}))
        with self.assertRaises(kgctl.PolicyError) as cm:
            kgctl.build_plan(base_policy(exec={"allow": [{"path": str(self.exe), "sha256": "0" * 64}]}))
        self.assertIn("sha256 mismatch", str(cm.exception))

    def test_egress_expansion_hosts_and_ports(self):
        net = {"egress_default": "deny",
               "allow": [{"host": "api.example", "ports": [80, 443]}, {"ip": "10.0.0.5", "port": 0}]}
        plan = kgctl.build_plan(base_policy(exec={"allow": [str(self.exe)]}, network=net),
                                resolver=lambda h: ["1.2.3.4", "5.6.7.8"])
        keys = self.keys(plan, "egress_allow")
        self.assertEqual(len(keys), 2 * 2 + 1)
        self.assertIn(kgctl.pack_egress_key(1, "1.2.3.4", 443), keys)
        self.assertIn(kgctl.pack_egress_key(1, "10.0.0.5", 0), keys)

    def test_ipv6_literal_is_rejected_not_silently_ignored(self):
        net = {"allow": [{"ip": "::1", "port": 1}]}
        with self.assertRaises(kgctl.PolicyError):
            kgctl.build_plan(base_policy(exec={"allow": [str(self.exe)]}, network=net))

    def test_unresolvable_host_is_an_error(self):
        def boom(_h):
            raise socket.gaierror("nope")
        net = {"allow": [{"host": "x.invalid", "port": 1}]}
        with self.assertRaises(kgctl.PolicyError):
            kgctl.build_plan(base_policy(exec={"allow": [str(self.exe)]}, network=net), resolver=boom)

    def test_sensitive_names_values(self):
        p = base_policy(exec={"allow": [str(self.exe)]})
        p["sensitive"] = {"taint": [".env"], "deny": ["shadow"]}
        entries = dict(kgctl.build_plan(p)["maps"]["sensitive_names"])
        self.assertEqual(entries[kgctl.pack_name_key(".env")], bytes([kgctl.SENS_TAINT]))
        self.assertEqual(entries[kgctl.pack_name_key("shadow")], bytes([kgctl.SENS_DENY]))

    def test_notes_warn_about_audit_mode_and_permissive_egress(self):
        plan = kgctl.build_plan(base_policy(mode="audit", exec={"allow": [str(self.exe)]},
                                            network={"egress_default": "allow"}))
        text = " ".join(plan["notes"])
        self.assertIn("AUDIT", text)
        self.assertIn("egress_default=allow", text)

    def test_example_policy_in_repo_validates(self):
        pol = kgctl.load_policy(ROOT / "policy" / "policy.example.yaml")
        kgctl.validate_policy(pol)


class TestRuns(unittest.TestCase):
    def test_find_run_by_name_picks_newest_and_by_cgid(self):
        state = {"runs": {"10": {"agent": "a", "started": 1}, "11": {"agent": "a", "started": 5},
                          "12": {"agent": "b", "started": 9}}}
        self.assertEqual(kgctl._find_run(state, "a")[0], 11)
        self.assertEqual(kgctl._find_run(state, "10")[0], 10)
        with self.assertRaises(kgctl.CtlError):
            kgctl._find_run(state, "zzz")


if __name__ == "__main__":
    unittest.main()
