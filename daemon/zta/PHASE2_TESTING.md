# Phase 2 – YAML-driven ZTA policy testing

## 1. Build

Run from the repository root:

```bash
cd ~/kernelguard
make -C daemon/zta clean
make -C daemon/zta
```

The build regenerates:
- `ebpf/zta/zta_enforcer.bpf.o`
- `ebpf/zta/zta_enforcer.skel.h`
- `daemon/zta/zta_controller`

The controller links against libbpf and libyaml using pkg-config.

## 2. Start the test agent

Terminal 1:

```bash
cd ~/kernelguard
python3 tests/zta/zta_profile_test_agent.py
```

Copy the printed `TEST_AGENT_PID`.

## 3. Start the ZTA controller

Terminal 2 (replace PID with the value from Terminal 1):

```bash
cd ~/kernelguard
sudo env LD_LIBRARY_PATH="$HOME/.local/lib64" \
  ./daemon/zta/zta_controller <PID> research_agent policies/policy.yaml
```

The controller loads the selected profile, populates the `execution_policy` BPF map, and registers the PID with that profile ID.

## 4. Verify ALLOW and DENY

In Terminal 1, enter:

```text
allow
deny
```

Expected:
- `allow`: `/usr/bin/ls` executes and returns 0.
- `deny`: `/bin/bash` is denied; the Python subprocess returns a non-zero code (normally 1) and does not print `BASH_EXECUTED`.

The `research_agent` profile in `policies/policy.yaml` allows Python and denies bash/sh. Unlisted executables are non-blocking (REVIEW/monitor-only), not implicitly denied.

## 5. Verify agent-specific profiles

Stop the first controller with Ctrl+C. Start it again with the same test-agent PID but use `code_agent`:

```bash
sudo env LD_LIBRARY_PATH="$HOME/.local/lib64" \
  ./daemon/zta/zta_controller <PID> code_agent policies/policy.yaml
```

Enter `deny` in Terminal 1. The current YAML allows `/bin/bash` for `code_agent`, so the child bash command should execute and print `BASH_EXECUTED`.

## 6. Verify policy reload

Use a temporary policy file so the tracked policy is not changed:

```bash
cd ~/kernelguard
cp policies/policy.yaml /tmp/kernelguard-policy-test.yaml
```

Start the controller with that file as the third argument. In another terminal, edit the temporary file to remove `/bin/bash` from `research_agent.execution.deny`, then send SIGHUP to the controller:

```bash
sudo kill -HUP <CONTROLLER_PID>
```

The controller should print `Policy reload successful`. A subsequent `deny` command should now run bash. Add `/bin/bash` back to the deny list, send SIGHUP again, and verify that bash is blocked again.

## 7. Important behavior and scope

- Only explicit entries under the selected agent profile's `execution.allow` and `execution.deny` are loaded into the enforcement map.
- Explicit DENY is enforced by the eBPF-LSM hook with `-EPERM`.
- Explicit ALLOW is non-blocking.
- Unlisted paths are non-blocking and should be treated as REVIEW/monitor-only. This implementation does not impose a strict default-deny allowlist.
- The global `security_monitor.execution_policy` risk categories remain handled by the existing user-space monitoring reader; they are not automatically kernel-deny rules.
- The current controller instance registers one agent PID/profile. Run a separate controller instance for each agent process tree.
- Policy reload is triggered with SIGHUP. The policy is parsed and validated before the active map is replaced.

## 8. Completion evidence

Do not mark Phase 2 complete until you have recorded:
1. Successful clean build.
2. `research_agent`: ls allowed, bash denied.
3. `code_agent`: bash allowed.
4. SIGHUP reload changes enforcement without restarting the controller.
5. Existing unrelated processes remain unaffected.
