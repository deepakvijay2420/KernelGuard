# KernelGuard Live Demonstration Guide

This guide is for a controlled Ubuntu VM demonstration. Run only on a disposable/test VM with administrator access. Use synthetic files and a test policy; never point the experiment at real credentials or production workloads.

## What the demonstration proves

The Core implementation uses eBPF-LSM hooks and cgroup-scoped agent identity to apply selected executable, sensitive-file, and network policies. The userspace controller prepares the cgroup, registers its cgroup ID in BPF maps, starts the workload as an unprivileged account, and cleans up the registration after the workload exits.

The demonstration does **not** prove semantic prompt-injection detection. It demonstrates that an OS operation attempted by a managed workload can be allowed or rejected by the configured kernel policy.

## 1. Preflight

From the active Core source directory:

```bash
cd ~/Amrita/KernelGuard/KernelGuard-Core
uname -r
sudo python3 kgctl.py doctor
```

Resolve every `FAIL` reported by doctor before continuing. Required facilities include BPF-LSM, kernel BTF, cgroup v2, bpffs, bpftool, and a supported BPF toolchain. Do not proceed if the VM does not support the required hooks.

## 2. Build and run unit tests

```bash
make clean
make -j2
python3 -m unittest discover -s tests -v
```

Expected unit-test result for the supplied source snapshot: 30 tests pass. This validates controller logic and policy planning; it does not prove kernel verifier acceptance or runtime enforcement.

## 3. Validate the policy

```bash
python3 tools/policy_lint.py policy/policy.hardened.yaml
sudo python3 kgctl.py plan -p policy/policy.hardened.yaml
```

Review the policy before applying it. Confirm the `run_as` account exists, configured executable paths exist, work directories are suitable, and resource limits are supported by the host cgroup hierarchy.

## 4. Load and apply

```bash
sudo python3 kgctl.py load
sudo python3 kgctl.py apply -p policy/policy.hardened.yaml
sudo python3 kgctl.py status
```

If load or apply fails, stop and inspect the error. Do not continue with an unconfirmed policy state.

## 5. Run a controlled agent workload

First confirm the policy's agent name and mode. The example hardened policy defines `research_agent`. Start with an explicitly permitted command:

```bash
sudo python3 kgctl.py run research_agent -- /usr/bin/ls /
```

Then try a harmless executable that is not on that agent's executable allow-list, for example `/usr/bin/id`, **only if the current policy does not allow it**:

```bash
sudo python3 kgctl.py run research_agent -- /usr/bin/id
```

Expected result for an enforce-mode policy: the unapproved executable is refused, typically with an `EPERM` / `Operation not permitted` message. Record the actual exit code and event. If the policy is in audit mode, the operation may be allowed; do not describe that as enforcement.

## 6. Sensitive-file and taint tests

Use a dedicated synthetic directory and synthetic data only:

```bash
sudo install -d -m 0755 /tmp/kg-demo
printf 'PUBLIC_DEMO_DATA\n' | sudo tee /tmp/kg-demo/public.txt >/dev/null
printf 'SYNTHETIC_SECRET=NOT_A_REAL_CREDENTIAL\n' | sudo tee /tmp/kg-demo/.env >/dev/null
printf 'SYNTHETIC_SHADOW_MARKER\n' | sudo tee /tmp/kg-demo/shadow >/dev/null
sudo chmod 0644 /tmp/kg-demo/public.txt /tmp/kg-demo/.env /tmp/kg-demo/shadow
```

The active policy must contain the matching sensitive filename rules. In `policy/policy.hardened.yaml`, `.env` is a taint filename and `shadow` is a deny filename. Confirm the exact rules in the policy you apply before demonstrating.

Run the synthetic file tests:

```bash
# Reading .env is permitted but should mark this workload as tainted.
sudo python3 kgctl.py run research_agent -- /usr/bin/python3 -c "print(open('/tmp/kg-demo/.env').read())"

# Reading a file whose final component is shadow should be denied.
sudo python3 kgctl.py run research_agent -- /usr/bin/python3 -c "import pathlib; p=pathlib.Path('/tmp/kg-demo/shadow'); print(p.read_text())"
```

The second command should produce a permission error if the deny rule is active. Check the corresponding `file_open / deny` event. The `.env` read should produce a `file_open / taint` event.

To demonstrate taint-based network restriction, read the synthetic `.env` and attempt the connection in the **same managed process/cgroup**:

```bash
sudo python3 kgctl.py run research_agent -- /usr/bin/python3 -c "import socket; open('/tmp/kg-demo/.env').read(); s=socket.socket(); s.settimeout(4); s.connect(('1.1.1.1',443))"
```

Expected result under the supplied taint policy: the connection attempt is rejected with `PermissionError` / `Operation not permitted`, and the event stream records `connect / deny`. If the network is unavailable for unrelated reasons, use the event verdict to distinguish KernelGuard denial from an ordinary network failure.

Do not use `/etc/shadow`, `/etc/sudoers`, SSH private keys, real API keys, or any production secret for testing.

## 7. Observe events and cleanup

```bash
sudo python3 kgctl.py events
```

In another terminal, run the test workload. Stop the event reader with Ctrl-C after collecting the events. Then inspect:

```bash
sudo python3 kgctl.py status
```

The controller should report no active demo run after the workload exits. Confirm that the matching cgroup has been removed before unloading.

```bash
sudo python3 kgctl.py unload
sudo rm -rf /tmp/kg-demo
```

Do not use `unload --force` while a managed agent is still running; it can leave that workload without the intended BPF protection.

## Suggested 8-minute guide presentation

1. **Problem (1 min):** an AI agent can invoke OS tools; application-level instructions are not a kernel security boundary.
2. **Architecture (1 min):** administrator policy → userspace controller → cgroup identity/BPF maps → eBPF-LSM hooks → allow/deny and events.
3. **Preflight/build (1 min):** show `doctor`, build and unit-test result.
4. **Allowed action (1 min):** run an allowed command in the registered agent cgroup.
5. **Blocked action (1 min):** attempt an unapproved executable and show the real error/event.
6. **File/taint/network policy (2 min):** use synthetic test data and explain the exact policy behaviour.
7. **Limitations (1 min):** selected hooks only; no semantic prompt-injection classifier; no claim that ML/LLM is in the syscall path; kernel enforcement must be demonstrated on the target VM.

## Evidence checklist

For each test, retain the exact policy file and its SHA-256, command, timestamp, exit status, relevant event JSON, and cleanup status. Separate successful policy planning/unit tests from successful kernel-level enforcement. A build alone is not proof of enforcement.
