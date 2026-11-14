# KernelGuard — Unified Runtime Security

This directory is the canonical implementation layout. It combines the agent example, BPF-LSM enforcement core, controller, policies, event reader, tests and behavioural-analysis research modules.

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
- `detection/`: behavioural features, ML inference wrapper and risk fusion.
- `dataset/`: dataset methodology and scenario generators.

## API key

The LangChain Google integration normally reads `GOOGLE_API_KEY` from the agent process environment. Set it in the controller's environment and list only the variable name in `env_passthrough`. Never commit or print the key. The agent can access a key passed to its environment; this is not a secret vault.

## Documentation

- [Complete code architecture](ARCHITECTURE.md)
- [Dataset methodology](dataset/README.md)
- [Root project overview](../README.md)

## Integration status

BPF-LSM policy is the enforcement authority. Behavioural ML and dataset work are currently separate analysis/evaluation components; existing collectors parse legacy monitor logs, not the current BPF ring-buffer JSON schema.
