# KernelGuard Core Architecture

## 1. Overview

KernelGuard places a kernel-enforced Zero Trust boundary around a managed Agentic AI workload. The controller assigns the workload a cgroup-v2 identity and loads administrator-defined policy into BPF maps. BPF-LSM hooks check selected operating-system actions against that policy.

## 2. Architecture

```text
        Administrator
             |
        YAML Policy
             |
             v
        kgctl.py
       /        \
      v          v
 cgroup v2    BPF Maps
 identity        |
      |          |
      v          |
 Managed Agent   |
      |          |
      +-- OS action
             |
             v
         BPF-LSM
             |
        Policy check
             |
      ALLOW / AUDIT / DENY
             |
             v
       BPF Ring Buffer
             |
             v
        kg_events
```

## 3. Main components

### ZTA controller — `kgctl.py`

The controller validates administrator-owned YAML policies, prepares BPF map entries, loads and attaches the BPF object, creates cgroup-v2 workloads, registers workload identity and manages workload lifecycle.

The controller also applies privilege reduction and configured cgroup resource limits. The managed agent does not own or modify the administrator policy.

### eBPF-LSM — `bpf/kg_zta.bpf.c`

The BPF program attaches to selected Linux Security Module hooks. It obtains the current cgroup ID, checks whether the process belongs to a managed workload, looks up the relevant policy maps and returns an allow or denial decision where the hook supports enforcement.

The current source covers selected executable, file-open, network, BPF and ptrace-related operations. This is not complete mediation of every Linux operation.

### Workload identity

The controller creates a dedicated cgroup-v2 directory for each managed workload and registers its cgroup ID in a BPF map. Child processes inherit the cgroup membership, allowing the hooks to associate their operations with the managed workload.

This is workload identity, not cryptographic proof of model identity or prompt provenance.

### Policy

The administrator defines policy in YAML. The controller validates and translates supported policy entries into BPF map state.

- Executable rules use executable file identity.
- Sensitive filename rules can deny an open or mark the workload as tainted.
- Tainted workloads are subject to configured IPv4 destination and port restrictions.
- Audit mode records would-deny decisions while allowing the operation.
- Enforce mode rejects covered operations when the active policy denies them.

### Event telemetry

The BPF program writes supported security events to a ring buffer. The user-space `kg_events` reader formats these events for inspection. Event telemetry is not an ML inference pipeline.

## 4. Runtime sequence

1. Administrator writes and reviews the YAML policy.
2. Controller validates the policy.
3. Controller loads and attaches the BPF-LSM programs.
4. Controller applies policy entries to BPF maps.
5. Controller creates a cgroup-v2 workload and registers its identity.
6. The managed agent performs operating-system actions.
7. BPF-LSM hooks check covered operations and emit events.
8. The event reader displays the recorded decisions.
9. The controller performs the requested workload lifecycle action when instructed by the operator.

## 5. Security boundaries and limitations

- KernelGuard checks selected OS actions, not natural-language prompts.
- It cannot inspect encrypted HTTPS request bodies or URL paths.
- Current egress allow-listing is IPv4-focused; IPv6 is not equivalently filtered.
- Allowing an interpreter does not restrict what scripts it can execute.
- Filename-component rules are not complete file-system mediation.
- KernelGuard assumes a trusted Linux kernel and privileged controller.
- Behavioural analysis and ML detection are not implemented; they are future scope.

## 6. Source layout

```text
kernelguard/
├── agent/
├── bpf/
├── policy/
├── tests/
├── tools/
├── systemd/
├── kgctl.py
├── Makefile
└── README.md
```
