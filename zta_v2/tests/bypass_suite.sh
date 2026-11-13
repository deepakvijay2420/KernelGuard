#!/usr/bin/env bash
# KernelGuard ZTA v2 - bypass test suite.
#
# Run on a LAB machine (real Ubuntu VM, not WSL2 unless you built a BPF-LSM kernel), as root:
#
#     cd zta_v2 && make && sudo tests/bypass_suite.sh
#
# What it does:
#   1. kgctl.py doctor            (aborts if the machine cannot enforce)
#   2. loads the programs, applies tests/policy.test.yaml
#   3. starts the event stream, runs tests/attack_probe.py as two confined agents
#   4. prints PASS/FAIL per attempt and checks the kernel really emitted deny/taint events
# Exit status 0 only if every bypass attempt was refused AND every control still worked.

set -u
cd "$(dirname "$0")/.."
KG="python3 ./kgctl.py"
POLICY="tests/policy.test.yaml"
EVENTS="$(mktemp /tmp/kg_events.XXXXXX.jsonl)"
FAIL=0
RES="${KG_RESULTS_DIR:-}"     # set by eval/run_eval.py to keep raw evidence
[ -n "$RES" ] && mkdir -p "$RES"

if [ "$(id -u)" -ne 0 ]; then echo "run as root"; exit 2; fi
id kgagent >/dev/null 2>&1 || useradd --system --no-create-home kgagent

echo "== doctor =="
$KG doctor || { echo "machine cannot run BPF-LSM enforcement; fix the FAIL lines first"; exit 2; }

echo "== load + apply =="
$KG unload --force >/dev/null 2>&1 || true
$KG load  || exit 2
$KG apply -p "$POLICY" || { $KG unload --force; exit 2; }

echo "== start event stream =="
$KG events > "$EVENTS" 2>/dev/null &
EV_PID=$!
sleep 1

run_probe() {   # $1 = agent, $2 = scenario
    local agent="$1" scenario="$2" work="/var/lib/kernelguard/work/$1"
    mkdir -p "$work"
    install -m 0644 tests/attack_probe.py "$work/attack_probe.py"
    chown -R kgagent "$work"
    echo "== agent $agent / scenario $scenario =="
    $KG run "$agent" -- /usr/bin/python3 "$work/attack_probe.py" --scenario "$scenario" | tee "$work/result.jsonl"
    local rc="${PIPESTATUS[0]}"
    [ -n "$RES" ] && cp "$work/result.jsonl" "$RES/probe_$2.jsonl"
    return "$rc"
}

run_probe probe_strict strict || FAIL=1
run_probe probe_taint  taint  || FAIL=1

sleep 1
kill "$EV_PID" 2>/dev/null; wait "$EV_PID" 2>/dev/null

echo "== kernel-side evidence =="
python3 - "$EVENTS" <<'PY' || FAIL=1
import collections, json, sys
c = collections.Counter()
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    c[(e["hook"], e["verdict"])] += 1
for (hook, verdict), n in sorted(c.items()):
    print(f"  {hook:10} {verdict:10} {n}")
need = [("exec", "deny"), ("file_open", "deny"), ("file_open", "taint"),
        ("connect", "deny"), ("sendmsg", "deny"), ("ptrace", "deny")]
missing = [n for n in need if c[n] == 0]
if missing:
    print("MISSING kernel events:", missing)
    sys.exit(1)
print("all expected hooks fired")
PY

[ -n "$RES" ] && cp "$EVENTS" "$RES/kernel_events.jsonl"
$KG unload --force >/dev/null
rm -f "$EVENTS"

if [ "$FAIL" -eq 0 ]; then echo "RESULT: PASS - every bypass attempt was refused"; else echo "RESULT: FAIL"; fi
exit "$FAIL"
