# Historical source directories

The canonical implementation is under `kernelguard/`. The following top-level directories remain in this branch because they contain earlier prototypes, experiment scripts, and compatibility material:

| Historical path | Notes |
|---|---|
| `agents/` | Earlier agent examples and prompt-injection experiments. The current canonical Gemini example is copied to `kernelguard/agent/`. |
| `ebpf/` | Earlier execution monitor and CO-RE header still used as a header source by the canonical Makefile. |
| `daemon/` | Earlier policy-engine/controller experiments; not the active controller. |
| `policies/` and root `policy.yaml` | Earlier policy formats. The current canonical policy schema is in `kernelguard/policy/`. |
| `model/` | Original ML experiment and training scripts. The canonical inference/feature/fusion modules are copied to `kernelguard/detection/`; original experiment scripts and artifacts remain here. |
| `dataset/` | Original generated dataset, CSVs, and experiment collectors. Canonical generator copies and methodology are under `kernelguard/dataset/`. |
| `zta_v2/` | Earlier ZTA implementation snapshot. The active canonical copy is under `kernelguard/`. |

These directories are not silently deleted or assumed to be integrated. Some canonical components still depend on historical formats: notably, the dataset collectors parse the earlier text log schema, and the canonical BPF Makefile currently uses `../ebpf/vmlinux.h` as its CO-RE header fallback.

Do not remove or rename these paths until the unified source has passed clean-checkout build, unit tests, BPF verifier/attach tests, and controlled runtime tests. New active development belongs under `kernelguard/`.
