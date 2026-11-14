# Unified KernelGuard migration

The canonical implementation is under `kernelguard/`. The previous top-level experiments and `zta_v2/` tree are retained as historical source snapshots while the unified layout is validated.

## Migration policy
- New active development goes into `kernelguard/`.
- Do not delete historical files until functionality, dependencies, tests and runtime ownership have been compared.
- Do not assume legacy ML log collectors consume the new BPF ring-buffer schema.
- Do not claim live enforcement or ML integration from dry-run/unit-test results.
- Preserve existing Git branches; this work is isolated on `unified-kernelguard`.

## Canonical components copied
Current ZTA controller, BPF-LSM program, shared header, policy examples, event reader, controller tests, safe dry-run script, LangChain/Gemini agent example, behavioural feature/ML/risk modules, and dataset guide/generators.

## Next integration tasks
1. Verify canonical paths and Makefile in a clean checkout.
2. Run Python/shell syntax checks and controller unit tests.
3. Compile the BPF object and event reader in the target VM.
4. Inspect existing BPF links/pins before any load or unload.
5. Test audit and enforce behaviour in a disposable VM.
6. Add a schema adapter and tested event-to-feature pipeline before claiming ML integration.
7. Configure model artifact paths and verify artifact provenance.
8. Retire duplicated historical source directories only after parity is demonstrated.
