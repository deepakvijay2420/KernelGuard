# Detection integration status

## Implemented in source

- BPF ring-buffer JSON event reader (`tools/kg_events.c`).
- Explicit schema adapter (`detection/event_adapter.py`).
- Adapter unit tests (`tests/test_event_adapter.py`).
- Existing 23-feature extractor (`detection/behavior_features.py`).
- Optional ML inference wrapper (`detection/behavior_ml.py`), requiring external artifacts.
- Risk fusion decision helper (`detection/risk_fusion.py`).

## Not yet implemented or verified

- A long-running Python process consuming JSONL from the reader.
- Bounded per-agent/cgroup event windows and window expiration.
- Valid trained model and feature-list artifacts with provenance.
- A verified call from feature extraction to model inference in runtime.
- A controller API consumer that turns a reviewed decision into an approved `kgctl.py tier` action.
- End-to-end tests on the target kernel from agent command through BPF event and reporting.
- BPF verifier/attach and audit/enforce integration results from a clean target VM.

## Semantics requiring attention

The BPF event timestamp `ts_ns` comes from monotonic kernel time, not Unix
wall-clock time. The adapter retains the exact value and uses a relative
representation for duration features. The current event does not provide UID,
so UID-related features are unavailable and remain zero. The event's `name`
field is not guaranteed to be a complete file path across all hooks.

No claim of ML-based blocking should be made until the complete event-to-model
and response chain is implemented and tested. BPF-LSM policy remains the
synchronous enforcement authority.
