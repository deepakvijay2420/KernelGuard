# KernelGuard

## A Kernel-Level Runtime Security Framework for Agentic AI Systems Using eBPF and Zero Trust Architecture

KernelGuard is a Linux runtime security research prototype designed to monitor, analyze, authorize, and control actions performed by Agentic AI systems.

The project addresses a security problem created when an AI agent is connected to operating-system tools such as files, shell commands, processes, and other system resources.

An Agentic AI system can normally generate text, but when it is given tools it can also cause real operating-system actions. A malicious or manipulated instruction can therefore cause an AI agent to perform an unintended action.

KernelGuard places security enforcement close to the Linux kernel and combines:

- eBPF / BPF-LSM for kernel-level monitoring and enforcement
- BPF Ring Buffer for kernel-to-user-space event delivery
- Zero Trust Architecture (ZTA) for agent-specific authorization
- Process provenance for identifying agent-controlled processes
- Behavioral Machine Learning for detecting suspicious execution patterns
- Risk Fusion for combining authorization and behavioral risk
- LangChain for Agentic AI integration
- Prompt-injection attack simulation
- Deterministic kernel-level enforcement

The central design principle is:

> Machine Learning and AI-based analysis can identify suspicious behavior, but deterministic kernel-level policy remains the final enforcement authority.

---

# 1. Project Overview

KernelGuard is designed as a runtime security layer between an Agentic AI system and the Linux operating system.

The system observes executable actions at the Linux kernel boundary and determines whether the action should be:

- ALLOWED
- REVIEWED
- WARNED
- DENIED

The current prototype focuses primarily on process execution monitoring using the Linux BPF-LSM hook:

`bprm_check_security`

The system can observe information such as:

- Process ID
- User ID
- Process name
- Executable path
- Execution frequency
- Process changes
- Path diversity
- Temporal behavior

The information is then processed by different security layers.

---

# 2. Problem Statement

Traditional AI safety mechanisms usually operate at the application or prompt level.

However, an Agentic AI system can interact with the host operating system.

For example:

```text
User
  |
  v
Agentic AI
  |
  +----> Read file
  |
  +----> Execute program
  |
  +----> Run shell command
  |
  +----> Access sensitive resource
  |
  v
Linux Operating System
