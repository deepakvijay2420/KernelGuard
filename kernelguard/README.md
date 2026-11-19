# KernelGuard — Unified Runtime Security

This directory is the canonical runtime implementation. It contains the agent example, BPF-LSM enforcement core, ZTA controller, policies, event reader and tests.

## Safe quick start

```bash
python3 kgctl.py plan -p policy/policy.example.yaml
make test
bash tests/dry_run.sh
```

Build and inspect prerequisites only after installing compiler/libbpf/bpftool dependencies:

```bash
make
python3 kgctl.py doctor
```

Do not load or detach BPF programs on a shared host without inspecting existing programs, links and pins and confirming ownership. Use a disposable VM for live tests.

## Components

- `agent/`: LangChain + Gemini agent and controlled Python tools.
- `kgctl.py`: YAML validation, BPF loading/map updates, cgroup lifecycle, privilege drop and response tiers.
- `bpf/`: BPF-LSM hooks and shared map/event structures.
- `policy/`: administrator-authored policies.
- `tools/`: JSON ring-buffer reader and policy lint.
- `tests/`: unit tests, safe dry run and controlled probes.

## API key

The LangChain Google integration normally reads `GOOGLE_API_KEY` from the agent process environment. Set it in the controller's environment and list only the variable name in `env_passthrough`. Never commit or print the key. The agent can access a key passed to its environment; this is not a secret vault.

## Documentation

- [Complete code architecture](ARCHITECTURE.md)
- [Dataset methodology](dataset/README.md)
- [Root project overview](../README.md)

## Current implementation status

The active controller includes fail-closed cgroup resource-limit setup and safer workload lifecycle cleanup: configured cgroup controllers and limit files are checked, values are read back, descendants are terminated, and BPF identity/run state is retained if the controller cannot verify an empty cgroup.

The supplied Ubuntu Stage 3/Stage 5 reports record 30 unit tests passing and selected enforce-mode tests: an unapproved executable was refused with EPERM, a synthetic `.env` read tainted the workload, a synthetic file named `shadow` was denied, and a tainted workload's test connection to `1.1.1.1:443` was denied. These results are environment-specific and do not prove universal coverage. See [stage validation evidence](../evidence/stage-validation/) and the [live demo guide](../docs/LIVE_DEMO_GUIDE.md).

Behavioural analysis, ML-based detection, dataset-driven classification, model inference and ML-driven response are **future scope**. They are not implemented in the current KernelGuard runtime. Historical or experimental files retained elsewhere in the repository are not active features and must not be presented as completed implementation.

Run the unit tests, BPF build, verifier/load/attach checks and live enforcement matrix on the target Ubuntu VM before describing a new checkout as validated.
