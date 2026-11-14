# Research positioning, related work and novelty

## Scope

KernelGuard studies a Linux OS-level security boundary for AI-agent workloads. The focus is not prompt classification inside the kernel. The focus is constraining selected operating-system consequences of agent tool use.

## Related research directions

- eBPF/BPF-LSM provides kernel-visible enforcement and telemetry for process, file and network operations.
- eBPF-based runtime detection work combines kernel events with ML features to classify suspicious workloads.
- Application-layer agent security systems mediate tool calls, validate arguments and apply capability policies.
- Recent agent-security work explores runtime policy enforcement, behavioural sandboxes and OS-level controls for tool-using agents.

Examples for literature review:
1. MCPGuard-Dynamic, kernel-level eBPF sandboxing for MCP tool calls: https://github.com/meta/mcpguard-dynamic
2. Runtime Protection Practice for LLM Agent Security: https://doi.org/10.1109/ISAEECE70502.2026.11635191
3. Runtime Policy Enforcement for MCP-Based LLM Agents: https://www.mdpi.com/2079-9292/15/13/2829
4. Hybrid Runtime Detection of Malicious Containers Using eBPF: https://doi.org/10.32604/cmc.2025.074871
5. Agentic AI as a Cybersecurity Attack Surface: https://arxiv.org/abs/2602.19555
6. SafeAgent: A Runtime Protection Architecture for Agentic Systems: https://arxiv.org/abs/2604.17562

These works are contextual references, not a head-to-head evaluation. Check publication details and versions before citing them in a paper.

## Defensible KernelGuard contribution

The current repository supports a contribution claim around the design and prototype integration of:
- cgroup-v2 workload identity associated with an agent process tree;
- administrator-authored YAML Zero Trust policy translated into BPF maps;
- BPF-LSM checks for executable identity, selected sensitive file opens, IPv4 egress, BPF syscall and ptrace;
- deterministic kernel policy separated from out-of-band behavioural ML;
- controlled workload dataset and multi-model evaluation with explicit provenance limitations.

## Novelty boundary

Do not claim KernelGuard is the first eBPF security system for AI agents. Existing projects already explore eBPF-based controls for LLM/MCP workloads. The defensible novelty must be stated as the particular architecture, policy model, integration, attack scenarios and evaluation demonstrated by this project.

The following remain future work, not completed contributions:
- verified live LLM prompt-injection-to-kernel-denial experiment;
- BPF JSON-to-ML dataset adapter and end-to-end telemetry pipeline;
- ML-triggered controller response with tested safety controls;
- independent benchmark and head-to-head comparison;
- verified enforce-mode results on the target kernel.
