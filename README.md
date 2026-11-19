# KernelGuard

**Linux runtime security for Agentic AI workloads using eBPF-LSM and Zero Trust Architecture (ZTA).**

KernelGuard is a research prototype that applies administrator-defined security policies to selected operating-system actions performed by a managed AI-agent workload.

The project focuses on controlling what an agent process can execute, which configured sensitive files it can access, and where a tainted workload can connect.

> **Scope:** The current implementation is the eBPF-LSM + cgroup-v2 + ZTA controller described below. Machine learning, behavioural analysis, datasets and model-based detection are not implemented and are not part of the current codebase.

## Implemented components

- **eBPF-LSM:** checks selected executable, file-open, network, BPF and ptrace operations.
- **cgroup v2 identity:** associates managed processes and their descendants with a registered workload identity.
- **ZTA controller:** validates administrator-owned YAML policy and updates BPF maps.
- **Executable control:** checks executable file identity against the configured allow-list.
- **Sensitive-file control:** applies configured filename rules to deny or taint a workload.
- **Network control:** applies configured IPv4 destination and port restrictions to a tainted workload.
- **Audit and enforce modes:** records policy decisions and, in enforce mode, rejects covered operations.
- **Event reader:** reads BPF ring-buffer events in user space.
- **Workload lifecycle controls:** applies privilege reduction, cgroup limits and managed workload response actions.

## Architecture

```text
Administrator YAML Policy
          |
          v
     kgctl.py (ZTA Controller)
          |
    +-----+------+
    |            |
    v            v
 cgroup v2     BPF Policy Maps
 identity          |
    |              |
    v              |
 Managed Agent     |
    |              |
    +--- OS action-+
          |
          v
      BPF-LSM Hooks
          |
     Policy Check
          |
    ALLOW / AUDIT / DENY
          |
          v
     BPF Ring Buffer
          |
          v
    kg_events Reader
```

The kernel enforces selected OS-level operations. It does not inspect prompt text, model reasoning or encrypted HTTPS request bodies. KernelGuard can restrict an unauthorised OS action caused by an agent; it does not claim semantic prompt-injection detection.

## Policy design and security inspection

KernelGuard's policy is the central part of its Zero Trust design. The administrator defines what each managed agent is allowed to do. The controller validates that YAML policy and translates it into BPF map entries. The eBPF-LSM program checks selected kernel operations against those entries at runtime.

The policy is not an AI prompt filter. It is an operating-system permission boundary around a workload: **which executable may start, which configured sensitive filenames may be opened, and which IPv4 destinations may be contacted.**

### 1. Where the policies are

All active policy files are under `kernelguard/policy/`:

| File | Purpose |
|---|---|
| `policy.example.yaml` | Small starting example for one research agent. |
| `policy.hardened.yaml` | More restrictive example with two separate agent profiles and a broader sensitive-file list. |
| `dangerous_commands.yaml` | Defensive command-name catalog used by the policy linter and tests. It is not itself a runtime BPF enforcement list. |

The administrator owns these files. The agent should not be allowed to edit the policy that governs its own permissions.

### 2. How a policy is created

A policy is written in YAML and starts with `version: 1`. It has two main parts:

- `sensitive`: global filename rules that apply to managed agents.
- `agents`: a separate configuration for each named workload.

Each agent profile defines an ID, operating mode, Linux account, working directory, environment variables, resource limits, executable allow-list and network rules.

Example based on the current `policy.hardened.yaml`:

```yaml
version: 1

sensitive:
  taint:
    - ".env"
    - "id_rsa"
    - "credentials.json"
  deny:
    - "shadow"
    - "sudoers"

agents:
  research_agent:
    id: 1
    mode: audit
    run_as: kgagent
    workdir: /var/lib/kernelguard/work/research_agent
    env_passthrough: [GOOGLE_API_KEY]
    limits:
      pids_max: 32
      memory_max: 536870912
    exec:
      allow:
        - /usr/bin/python3
        - /usr/bin/ls
        - /usr/bin/cat
        - /usr/bin/whoami
    network:
      egress_default: deny
      allow:
        - {host: generativelanguage.googleapis.com, port: 443}
        - {ip: 127.0.0.53, port: 53}
```

This is an explanatory extract, not a replacement for the complete policy file. The actual hardened policy contains additional sensitive filenames and a separate `code_agent` profile.

### 3. What each policy control does and why it matters

| Policy field | What we configure | Why it matters |
|---|---|---|
| `id` | Unique agent ID from 1 to 63 | Separates policy entries for different agent profiles in BPF maps. |
| `mode` | `audit` or `enforce` | Allows policy testing before switching to blocking. |
| `run_as` | Dedicated unprivileged Linux account such as `kgagent` | Reduces the privileges available to the agent process. |
| `workdir` | Dedicated workload directory | Gives the workload a defined working location. |
| `env_passthrough` | Explicit environment-variable allow-list | Avoids passing the complete parent environment to the agent. Only pass secrets the workload genuinely needs. |
| `limits.pids_max` | Maximum number of processes | Helps limit process-spawning abuse and fork-bomb impact through cgroup v2. |
| `limits.memory_max` | Memory ceiling in bytes | Helps limit memory exhaustion by the workload. |
| `exec.allow` | Explicit executable allow-list | Only listed executable file identities are authorised in enforce mode. |
| `sensitive.taint` | Sensitive filenames whose read is allowed but marks the workload | Allows a required read while recording that the workload has handled sensitive data. |
| `sensitive.deny` | Sensitive filenames that should not be opened by an agent | Defines files such as `shadow` and `sudoers` as prohibited targets. |
| `network.egress_default` | Default network posture: `deny` or `allow` | With `deny`, only explicitly listed IPv4 destinations and ports are allowed. |
| `network.allow` | Approved host/IP and port entries | Allows only the network destinations needed by the agent under the configured restriction state. |

### 4. The most important rule: executable allow-list

KernelGuard does not rely only on executable path strings. The controller resolves each configured executable and records its device and inode identity in the `exec_allow` BPF map, associated with the agent ID.

When a managed process attempts an execution, the BPF-LSM `bprm_check_security` hook checks the executable's device/inode identity:

1. If the identity is present in the agent's allow-list, the execution is allowed.
2. If it is absent, the operation is a policy violation.
3. In `audit` mode, the violation is recorded but not blocked.
4. In `enforce` mode, the hook returns `-EPERM` and blocks the covered execution.

This is stronger than a simple string comparison because changing a path, using a symlink or copying a binary to another location does not automatically make it the same allowed inode. The controller also supports an optional SHA-256 check for an executable entry when the policy includes a `sha256` value.

**Important limitation:** an allowed interpreter such as Python can execute scripts. Allow-listing the Python binary does not, by itself, restrict which Python code it interprets. The workload must therefore also be constrained by its filesystem permissions, environment, network policy and other controls.

### 5. Sensitive-file handling: deny versus taint

The policy deliberately has two different responses:

- **Deny:** the configured filename is prohibited. In enforce mode, a covered open attempt is rejected.
- **Taint:** the read is allowed, but KernelGuard marks the workload's cgroup state as having accessed sensitive data.

For example, `.env`, private-key names and credential stores are placed in the taint list in the hardened policy. Files such as `shadow`, `gshadow` and `sudoers` are placed in the deny list.

The BPF-LSM `file_open` hook checks the final component of the resolved filename against the configured sensitive-name map. This is a filename-based rule, not a complete path-based data-loss-prevention system. The current implementation limits configured names to 31 bytes.

**Why taint is useful:** sometimes an agent legitimately needs to read a credential or configuration file. Blocking every such read may break the task. Taint records that sensitive access happened, and the network policy can then restrict where that workload is allowed to send data.

### 6. Network policy and the sensitive-read response

The current network policy is IPv4-focused and checks selected `socket_connect` and `socket_sendmsg` operations.

The hardened example uses:

```yaml
network:
  egress_default: deny
  allow:
    - {host: generativelanguage.googleapis.com, port: 443}
    - {ip: 127.0.0.53, port: 53}
```

This expresses that the agent should contact only the approved IPv4 destinations and ports while the default-deny restriction applies. The hostname is resolved to IPv4 addresses when the controller builds/applies the policy; re-apply the policy to refresh those resolved addresses.

The BPF program also checks the workload's taint state. If the workload has read a taint-listed file, its egress is restricted to the configured allow-list even when its `egress_default` setting is `allow`.

**Example flow:**

1. The agent opens a configured `.env` file.
2. The file-open hook records a taint event and marks the workload's cgroup as tainted.
3. The agent later attempts an IPv4 connection.
4. The connect/sendmsg hook checks the destination and port against the allow-list.
5. A listed destination is allowed; an unlisted destination becomes a policy violation.

This is an OS-level containment response. It does not inspect the contents of an HTTPS request, identify a prompt injection, or prove that data was exfiltrated.

### 7. Why the hardened policy is stronger

Compared with the small example policy, `policy.hardened.yaml`:

- Defines two separate profiles, `research_agent` and `code_agent`, rather than one shared agent profile.
- Uses separate agent IDs so their executable and network entries can be associated with the correct profile.
- Includes a broader list of credential, key, browser-store, cloud, Kubernetes and infrastructure-state filenames for taint handling.
- Adds high-risk system files, host keys, container sockets and policy files to the deny list.
- Keeps executable permissions narrow and excludes shells, download tools, package managers, compilers and Git from the sample allow-lists.
- Uses default-deny network settings and explicitly lists the required destinations.
- Sets process and memory limits for each workload.
- Passes only the configured API-key environment variable instead of inheriting the full environment.

The `dangerous_commands.yaml` catalog groups risky command families such as privilege escalation, shells, network transfer, destructive operations, persistence, system changes, container tooling and package installation. The policy linter uses this catalog to reject dangerous executable entries in a policy. **The catalog is a validation safety net; actual runtime execution decisions are made from the compiled executable allow-list and BPF maps.**

### 8. Audit mode versus enforce mode — an important distinction

The committed `policy.hardened.yaml` currently sets both sample agents to `mode: audit`. This is intentional for safe rollout, but it means the sample is **not yet in blocking mode**.

| Mode | Behaviour on a policy violation |
|---|---|
| `audit` | Emits an `audit_deny` event, but allows the operation to continue. |
| `enforce` | Emits a deny event and the relevant BPF-LSM hook rejects the covered operation with `EPERM`. |

Recommended rollout:

1. Start in audit mode with a representative, non-production workload.
2. Inspect events using `python3 kgctl.py events`.
3. Identify legitimate operations that were flagged and adjust the policy deliberately.
4. Review the final allow-lists with the administrator.
5. Change the relevant agent profile to `mode: enforce`.
6. Re-validate the policy and repeat controlled tests.

Do not change to enforce mode blindly: an incomplete allow-list can stop the agent from performing legitimate work.

### 9. How the policy is protected and applied

The controller adds several protections around policy use:

- **Administrator-controlled policy:** the YAML file is supplied to the controller, not authored dynamically by the agent.
- **Validation before compilation:** the controller checks the policy version, agent IDs, modes, executable entries, network entries, limits and sensitive-name rules.
- **BPF map compilation:** validated rules are converted into kernel map keys and values for the executable, sensitive-name and egress maps.
- **Policy hash pinning:** the controller records a hash when the policy is applied. The run operation checks that the policy has not changed since application and refuses to start the workload if it detects drift.
- **Workload isolation:** the controller places the workload in its own cgroup-v2 identity and applies the configured resource limits.
- **Privilege reduction:** the workload is launched under the configured unprivileged account with a minimal environment and no-new-privileges protection.

The policy hash is a drift check, not a digital signature. It does not prove who authored the policy or protect against a privileged administrator or host compromise.

### 10. Validate and inspect a policy

From the `kernelguard/` directory:

```bash
# Validate the example policy and display the planned map entries
python3 kgctl.py plan -p policy/policy.example.yaml

# Inspect the hardened policy
python3 kgctl.py plan -p policy/policy.hardened.yaml

# Run the defensive policy linter
python3 tools/policy_lint.py policy/policy.hardened.yaml

# Review available controller commands
python3 kgctl.py --help
```

The plan and linter are useful before loading anything into the kernel. A successful plan is not proof that BPF verifier loading or live enforcement will succeed on a particular kernel. Perform live tests only in a disposable Ubuntu VM.

### 11. Current policy coverage and limitations

The current policy is deliberately stronger than a basic command blacklist, but it is not a complete sandbox or universal data-loss-prevention solution.

- Only selected BPF-LSM hooks and operations are mediated.
- Sensitive-file matching uses the final filename component, not a complete path and content inspection.
- Network allow-listing is IPv4-only; IPv6 is not equivalently filtered.
- Hostnames are resolved at policy application time; re-apply to refresh DNS results.
- Encrypted HTTPS payloads, URLs and prompt text are not inspected.
- An allowed interpreter can run scripts; executable identity is not script-level authorization.
- The dangerous-command catalog is a linter/test input, not an independent kernel enforcement mechanism.
- Audit mode logs violations but does not block them.
- The policy hash detects file changes after apply; it is not a cryptographic signature.

These boundaries are important when evaluating results: KernelGuard demonstrates policy-based control over selected OS actions of managed agent workloads, not complete prevention of every possible attack.

## Repository structure

```text
KernelGuard/
├── README.md
├── SECURITY.md
├── kernelguard/
│   ├── agent/       # Agent integration example
│   ├── bpf/         # eBPF-LSM source and shared definitions
│   ├── policy/      # Administrator YAML policies
│   ├── tests/       # Controller tests and controlled probes
│   ├── tools/       # Ring-buffer event reader and policy linter
│   ├── systemd/     # Optional service unit
│   ├── kgctl.py     # ZTA controller
│   ├── Makefile
│   └── README.md
├── docs/            # Current architecture and demo guide
└── evidence/        # Supplied Ubuntu validation reports
```

## Quick start

```bash
git clone https://github.com/deepakvijay2420/KernelGuard.git
cd KernelGuard/kernelguard

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install PyYAML

python3 kgctl.py plan -p policy/policy.example.yaml
python3 -m unittest discover -s tests -v
make
```

The BPF build requires a compatible Linux kernel and system dependencies including clang/LLVM with the BPF target, GCC, libbpf development headers and bpftool. Check the target machine with:

```bash
sudo python3 kgctl.py doctor
```

Do not load or detach BPF programs on a shared or production host. Perform live enforcement tests only in a disposable Ubuntu VM after checking kernel support and reviewing the policy.

## Current validation evidence

The reports in `evidence/stage-validation/` were supplied from an Ubuntu VM. They record 30 controller unit tests passing and selected tests for executable denial, synthetic sensitive-file taint/denial and taint-triggered IPv4 egress denial.

These are specific test results, not proof of universal attack coverage. Re-run the tests, BPF build, verifier/load/attach checks and live enforcement tests on a clean checkout before treating a new environment as validated.

## Limitations

- Prompt injection is not detected by analysing prompt text.
- Only selected operations covered by the implemented hooks are checked.
- IPv4 egress restrictions do not provide equivalent IPv6 filtering.
- Encrypted HTTPS content and URL paths are not inspected.
- Allowing an interpreter does not sandbox the scripts it executes.
- The project is a research prototype, not a production-ready security product.

## Future scope

Behavioural analysis, ML-based detection, dataset preparation, model evaluation and any model-driven risk response may be explored in future work. None of these capabilities is implemented in the current KernelGuard system.

## Documentation

- [KernelGuard implementation guide](kernelguard/README.md)
- [KernelGuard architecture](kernelguard/ARCHITECTURE.md)
- [Live demonstration guide](docs/LIVE_DEMO_GUIDE.md)
- [Validation evidence](evidence/stage-validation/README.md)
- [Security policy](SECURITY.md)
