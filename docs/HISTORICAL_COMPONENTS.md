# Historical source directories

The canonical implementation is under `kernelguard/`. The following top-level directories remain because they contain earlier prototypes, experiment scripts, and compatibility material:

| Historical path | Notes |
|---|---|
| `agents/` | Earlier agent examples and prompt-injection experiments. The current canonical Gemini example is copied to `kernelguard/agent/`. |
| `ebpf/` | Earlier execution monitor and ZTA code. The canonical BPF implementation now has its own `kernelguard/bpf/vmlinux.h` header copy. |
| `daemon/` | Earlier policy-engine/controller experiments; not the active controller. |
| `policies/` and root `policy.yaml` | Earlier policy formats. The canonical policy schema is in `kernelguard/policy/`. |
| `model/` | Original ML experiment and training scripts. Canonical feature/inference/fusion modules are copied to `kernelguard/detection/`; original experiments and artifacts remain here. |
| `dataset/` | Original generated dataset, CSVs, and experiment collectors. Canonical generator copies and methodology are under `kernelguard/dataset/`. |
| `zta_v2/` | Earlier ZTA implementation snapshot. The active canonical copy is under `kernelguard/`. |

These directories are not silently deleted or assumed to be integrated. The canonical dataset collectors still parse the earlier text log schema; they are not yet adapted to consume BPF ring-buffer JSON.

Do not remove or rename these paths until the unified source has passed clean-checkout build, unit tests, BPF verifier/attach tests, and controlled runtime tests. New active development belongs under `kernelguard/`.
