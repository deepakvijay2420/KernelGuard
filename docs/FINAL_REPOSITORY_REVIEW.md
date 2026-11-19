> **Status update — 19 November 2026:** This document records an earlier repository review and is retained for history. The current integration branch is `integration/latest-core-controller`. The latest hardened controller from the supplied Ubuntu `KernelGuard-Core/` snapshot has now been synchronized into the canonical `kernelguard/kgctl.py` path on this branch. Current implementation status, VM evidence and remaining ML integration work are documented in the root [README](../README.md) and [source-of-truth migration note](UNIFIED_MIGRATION.md). Do not treat branch-specific statements below as the current branch state.

---

# Final repository cleanup review

**Review branch:** `cleanup/final-repository-review`  
**Base:** `main`  
**Canonical implementation:** `kernelguard/`

## Changes made in this review

- Corrected the controller's missing-BPF-object diagnostic so it directs developers to build from the canonical `kernelguard/` directory. The old message incorrectly pointed to the historical `zta_v2/` directory.
- Updated the repository audit to describe this branch and the corrected canonical build guidance.
- Updated the migration note so it no longer refers to the previous cleanup branch.

## Confirmed preservation decisions

The review intentionally does not delete or rename historical source trees, datasets, ML training/evaluation code, model files, experiment results, agent demonstrations, or scripts. The root README and audit explain that these items must be checked for unique research value and references before retirement.

## Outstanding repository issue: libbpf-bootstrap gitlink

The prior local checkout inspection reported that `libbpf-bootstrap` is recorded as a Git submodule gitlink, but the repository has no matching `.gitmodules` mapping. The local directory also contained a populated checkout. This review does not remove the gitlink or its contents: the exact upstream URL and intended submodule commit must be confirmed before repairing or removing it.

## Validation status

The GitHub connector can update source files and inspect repository metadata, but it does not execute the project's Linux build, BPF verifier, or runtime tests. Therefore:

- The controller diagnostic change is a text-only path correction.
- No claim is made that BPF compilation, verifier loading, LSM attachment, ring-buffer delivery, audit enforcement, or enforce-mode blocking has been tested by this review.
- Run `make test`, `bash tests/dry_run.sh`, and the CI compile checks on a clean checkout.
- Perform live BPF tests only in a disposable Linux VM after inspecting existing BPF links and pins.

## Recommended next steps

1. Run the clean-checkout Python tests and dry-run policy validation.
2. Resolve the `libbpf-bootstrap` gitlink only after confirming its intended remote URL and whether any historical workflow still depends on it.
3. Complete the file-level reference/dependency audit before archiving duplicate trees.
4. Test BPF compilation, load/attach, event delivery, and audit/enforce behaviour on the target VM.
5. Merge this branch only after reviewing the PR diff and CI results.
