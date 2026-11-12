# KernelGuard v2 validation

- Date: 2026-11-13
- Branch: feature/zta-v2
- Remote: https://github.com/deepakvijay2420/KernelGuard.git
- Cgroup path: /sys/fs/cgroup/kernelguard-research-agent
- Current cgroup inode: 8638
- LangChain model: gemini-3.5-flash

## Observed evidence
- v2 BPF object and reader built successfully.
- Reader loaded six policy entries and attached the BPF-LSM execution hook.
- Benign LangChain agent and its ls/cat children were observed under cgroup 8638.
- A controlled agent attempt to execute /usr/bin/sudo was denied with PermissionError.
- Reader captured an EXEC attempt for /usr/bin/sudo under cgroup 8638.

## Limits
Current enforcement covers executable launches by cgroup ID and executable path. It does not yet enforce file or network operations. The controlled attack task is not proof of autonomous prompt-injection detection. A benign-system-prompt / malicious-document experiment remains future work. The cgroup inode changes if the cgroup is recreated; recompile policy after such a change.
