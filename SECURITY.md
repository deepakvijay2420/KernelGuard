# Security Policy

## Scope

KernelGuard is a research prototype for Linux runtime controls over designated agent workloads. Security reports may concern the BPF-LSM hooks, userspace controller, policy loader, cgroup-based workload identity, executable/file/network controls, or event pipeline.

## Safe testing

- Use an isolated disposable VM.
- Use synthetic files and harmless test commands.
- Do not test against production workloads or third-party systems without explicit authorization.
- Do not use real credentials, private keys, or system password files as test fixtures.
- Preserve the exact policy, command, kernel version, event output and cleanup result for reproducibility.

## Security boundaries

KernelGuard does not claim to withstand a compromised host kernel or an unrestricted host-root attacker. It does not semantically inspect prompts or encrypted HTTPS contents. It enforces selected OS operations at the implemented hooks; coverage depends on kernel configuration, policy and workload placement.

A successful unit test, policy plan or BPF compilation is not proof of runtime enforcement. Verify each enforcement claim with a reproducible test that observes the expected kernel denial and corresponding event.

## Vulnerability reporting

Please report suspected vulnerabilities privately to the repository maintainer before public disclosure. Include the affected revision, kernel version, configuration, minimal reproduction and relevant logs. Do not include real secrets or personal data in reports.
