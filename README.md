# KernelGuard

## A Kernel-Level Runtime Security Framework for Agentic AI Systems Using eBPF and Zero Trust Architecture

KernelGuard is a Linux runtime security research prototype designed to monitor, analyze, authorize, and control actions performed by Agentic AI systems.

Modern Agentic AI systems can do more than generate text. When connected to tools, files, shell commands, APIs, and operating-system resources, an AI agent can cause real system-level actions.

This creates a new security problem:

> An AI agent may be manipulated by malicious instructions and cause unintended operating-system actions.

KernelGuard addresses this problem by moving security enforcement close to the Linux kernel and combining:

- eBPF / BPF-LSM for kernel-level monitoring and enforcement
- Zero Trust Architecture (ZTA) for agent-specific authorization
- Agent process provenance for identifying agent-controlled processes
- Behavioral Machine Learning for detecting suspicious execution patterns
- Risk Fusion for combining authorization and behavioral risk
- Agentic AI integration using LangChain
- Prompt-injection attack simulation
- Deterministic kernel-level enforcement

The main design principle is:

> Machine Learning and AI-based analysis can identify suspicious behavior, but deterministic kernel-level policy remains the final enforcement authority.

---

# 1. Problem Statement

Agentic AI systems are different from traditional chatbots.

A traditional chatbot generally produces text.

An Agentic AI system can:

- execute programs
- read and modify files
- invoke shell commands
- access network resources
- call external tools
- interact with operating-system resources
- perform multi-step tasks autonomously

If an attacker can influence the instructions, files, tool outputs, or context consumed by the agent, the agent may perform an unintended action.

For example:

```text
User
  |
  v
Agentic AI
  |
  v
Read a malicious document
  |
  v
Prompt Injection
  |
  v
Agent decides to execute a privileged command
  |
  v
Linux process
  |
  v
Operating System
