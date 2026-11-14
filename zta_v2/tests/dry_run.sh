#!/usr/bin/env bash
# KernelGuard Stage 1 dry run.
# Safe: no root required; does not load/unload BPF, alter cgroups, or change policy maps.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

echo "== Environment =="
printf 'Kernel: '; uname -r
printf 'Python: '; python3 --version
printf 'Compiler: '; command -v gcc || true
printf 'Clang: '; command -v clang || true
printf 'bpftool: '; command -v bpftool || true

echo
echo "== Static syntax checks =="
python3 -m py_compile kgctl.py tests/test_kgctl.py tests/attack_probe.py
bash -n tests/bypass_suite.sh
echo "Python and shell syntax: PASS"

echo
echo "== Policy structure validation (no BPF interaction) =="
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
