# Archived implementation snapshots

These directories are retained for research provenance and rollback. They are not the active implementation.

- `agents/`: earlier LangChain agents, prompt-injection demonstration and supporting files.
- `daemon/`: earlier policy-engine and ZTA controller experiments.
- `ebpf/`: earlier execution monitor, reader and BPF source snapshots.
- `zta_v2/`: earlier ZTA controller, BPF source, policies and tests.
- `legacy-policies/`: earlier policy formats that predate the canonical version-1 schema.
- `legacy-scripts/`: setup and experiment scripts that refer to earlier directory layouts.

Use `kernelguard/` for current development. Archived code may have dependencies, assumptions, or hard-coded paths that are no longer valid after repository reorganisation. Do not delete archived files merely because they duplicate a current component; compare behaviour, tests and research value first.
