import json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
import kg_stats as K


class Stats(unittest.TestCase):
    def test_percentiles(self):
        s = list(range(1, 101))
        self.assertAlmostEqual(K.percentile(s, 50), 50.5)
        self.assertEqual(K.percentile(s, 100), 100)
        self.assertEqual(K.percentile([7], 99), 7.0)
        with self.assertRaises(ValueError):
            K.percentile([], 50)

    def test_summarize(self):
        r = K.summarize([4, 1, 3, 2])
        self.assertEqual((r["n"], r["min"], r["max"], r["median"]), (4, 1, 4, 2.5))

    def test_overhead_ci_brackets_truth_and_is_seeded(self):
        base = [100, 101, 99, 100, 102, 98, 100, 101]
        cond = [x * 1.10 for x in base]
        p, lo, hi = K.overhead_ci(base, cond)
        self.assertAlmostEqual(p, 10.0, places=6)
        self.assertLessEqual(lo, p)
        self.assertGreaterEqual(hi, p)
        self.assertEqual((p, lo, hi), K.overhead_ci(base, cond))      # deterministic
        z, zl, zh = K.overhead_ci(base, base)
        self.assertEqual(z, 0.0)
        with self.assertRaises(ValueError):
            K.overhead_ci([], [1])


class Parsing(unittest.TestCase):
    def test_probe_skips_banners(self):
        text = 'kgctl: starting\n{"name":"a","expect":"blocked","errno":1,"passed":true}\nnoise {x}\n{"bad":1}\n'
        rows = K.parse_probe_jsonl(text)
        self.assertEqual(len(rows), 1)

    def test_summary_flags_failures(self):
        rows = [{"name": "a", "expect": "blocked", "errno": 1, "passed": True},
                {"name": "b", "expect": "blocked", "errno": 0, "passed": False},
                {"name": "c", "expect": "allowed", "errno": 0, "passed": True}]
        s = K.bypass_summary(rows)
        self.assertEqual((s["attempts"], s["attempts_refused"], s["controls_ok"]), (2, 1, 1))
        self.assertFalse(s["all_passed"])
        self.assertFalse(K.bypass_summary([])["all_passed"])      # empty is never "passed"

    def test_events(self):
        t = '{"hook":"exec","verdict":"deny"}\n{"hook":"exec","verdict":"deny"}\ngarbage\n'
        self.assertEqual(K.parse_events_jsonl(t), {("exec", "deny"): 2})

    def test_errno_name(self):
        self.assertEqual(K.errno_name(1), "EPERM")
        self.assertEqual(K.errno_name(0), "success")
        self.assertEqual(K.errno_name(-2), "err-2")


class Latex(unittest.TestCase):
    def test_escape(self):
        self.assertEqual(K.tex_escape("a_b & 5%"), r"a\_b \& 5\%")

    def test_bypass_table_marks_fail_and_escapes(self):
        rows = [{"name": "exec: sym_link", "expect": "blocked", "errno": 1, "passed": True},
                {"name": "bad", "expect": "blocked", "errno": 0, "passed": False}]
        t = K.bypass_table_tex(rows)
        self.assertIn(r"exec: sym\_link", t)
        self.assertIn(r"\textbf{FAIL}", t)
        self.assertIn("EPERM", t)

    def test_overhead_table(self):
        s = {"exec": {"unloaded": {"summary": {"median": 1000.0}, "overhead": None},
                      "enforce": {"summary": {"median": 1100.0}, "overhead": (10.0, 8.0, 12.0)}}}
        t = K.overhead_table_tex(s)
        self.assertIn("1.1 (+10.0\\%)", t)
        self.assertIn("--", t)          # missing conditions render as a dash


if __name__ == "__main__":
    unittest.main()


class Render(unittest.TestCase):
    def test_end_to_end_on_synthetic_raw(self):
        import tempfile, random
        import render_results as R
        rng = random.Random(1)
        with tempfile.TemporaryDirectory() as d:
            raw = os.path.join(d, "raw")
            os.makedirs(raw)
            with open(os.path.join(raw, "probe_strict.jsonl"), "w") as f:
                f.write("banner\n")
                for i, ok in enumerate([True, True, False]):
                    f.write(json.dumps({"name": f"t_{i}", "expect": "blocked", "errno": 1 if ok else 0, "passed": ok}) + "\n")
                f.write(json.dumps({"name": "control", "expect": "allowed", "errno": 0, "passed": True}) + "\n")
            with open(os.path.join(raw, "kernel_events.jsonl"), "w") as f:
                f.write('{"hook":"exec","verdict":"deny"}\n')
            samples = []
            scale = {"unloaded": 1.0, "loaded_unconfined": 1.02, "audit": 1.1, "enforce": 1.2}
            for rnd in range(6):
                for c, k in scale.items():
                    phase = ("pre" if rnd < 3 else "post") if c == "unloaded" else "main"
                    ops = {op: [int(1000 * k * (1 + rng.random() * 0.05)) for _ in range(50)] for op in R.OPS}
                    samples.append({"round": rnd, "phase": phase, "condition": c, "ops": ops, "errors": {}})
            with open(os.path.join(raw, "overhead_raw.json"), "w") as f:
                json.dump({"meta": {"rounds": 6}, "samples": samples}, f)
            b, o = R.render(d)
            for name in ("bypass_results.csv", "table_bypass.tex", "table_overhead.tex",
                         "overhead_summary.csv", "SUMMARY.md", "kernel_events.csv"):
                self.assertTrue(os.path.exists(os.path.join(d, name)), name)
            self.assertFalse(b[1]["all_passed"])
            ov = o[0]["exec_true"]["enforce"]["overhead"]
            self.assertAlmostEqual(ov[0], 20.0, delta=3.0)
            self.assertLess(ov[1], ov[0] + 1e-9)
            md = open(os.path.join(d, "SUMMARY.md")).read()
            self.assertIn("Failures", md)
            self.assertIn("FAIL", md)
