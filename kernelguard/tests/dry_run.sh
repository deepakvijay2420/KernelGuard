#!/usr/bin/env bash
# Safe unified KernelGuard dry run: no root, BPF load/unload, map writes or cgroups.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

echo "== Environment =="
printf 'Kernel: '; uname -r
printf 'Python: '; python3 --version
printf 'Compiler: '; command -v gcc || true
printf 'Clang: '; command -v clang || true
printf 'bpftool: '; command -v bpftool || true

echo
echo "== Python and shell syntax =="
python3 -m py_compile kgctl.py tests/test_kgctl.py tests/attack_probe.py tools/policy_lint.py agent/langchain_gemini_agent.py detection/behavior_features.py detection/behavior_ml.py detection/risk_fusion.py dataset/generators/collect_attack_dataset.py dataset/generators/collect_benign_dataset.py dataset/generators/collect_composite_benign.py dataset/generators/generate_benign.py
bash -n tests/dry_run.sh
echo "Syntax checks: PASS"

echo
echo "== Policy validation (no BPF interaction) =="
python3 - <<'PY'
import kgctl
for path in ("policy/policy.example.yaml", "tests/policy.test.yaml"):
    policy = kgctl.load_policy(path)
    kgctl.validate_policy(policy)
    print(f"{path}: VALID")
PY

echo
echo "== Unit tests (no root / no BPF required) =="
make test

echo
echo "== Dry-run boundary =="
echo "PASS: no BPF programs were loaded or unloaded."
echo "PASS: no policy maps were changed."
echo "PASS: no cgroups or agent processes were created."
echo "NOTE: this does NOT prove kernel verifier acceptance or runtime enforcement."
echo "RESULT: DRY RUN COMPLETE"
