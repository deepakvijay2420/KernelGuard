# Stage validation evidence

These reports were copied from the supplied Ubuntu development snapshot dated 19 November 2026.

| Report | Recorded result |
|---|---|
| `kernelguard_stage3_report_20261119_063407.txt` | KernelGuard status, 30 controller unit tests, audit-mode allowed/recorded executable checks, and event output |
| `kernelguard_stage5_report_20261119_063610.txt` | Enforce-mode synthetic public-file read, `.env` taint, synthetic `shadow` denial, and taint-triggered denial of `1.1.1.1:443` |
| `kernelguard_enforce_report_20261119_063455.txt` | Enforce-mode allowed `whoami` and refused `/usr/bin/id` with EPERM |

## Interpretation

The reports are environment-specific evidence from the user's Ubuntu VM. They are not a guarantee for other kernels, configurations, policies or attack techniques.

The tests use synthetic files under temporary directories. They do not authorize testing against real `/etc/shadow`, `/etc/sudoers`, private keys or production credentials.

Stage 3 records 30 unit tests passing. Stage 5 records the kernel event verdicts and expected permission errors for the tested operations. Preserve the reports as captured evidence; do not rewrite their results into broader claims.

See [the live demo guide](../../docs/LIVE_DEMO_GUIDE.md) for a reproducible demonstration sequence and [the root README](../../README.md) for implementation status and limitations.
