# KernelGuard detection integration

This directory contains behavioural feature extraction, optional ML inference,
risk fusion, and the adapter from live BPF ring-buffer JSON to the feature schema.

## Current pipeline boundary

```text
kg_events (JSONL)
    -> event_adapter.normalize_bpf_events()
    -> behaviour_features.extract_from_events()
    -> behaviour_ml.BehaviorML.predict()  [requires trained joblib artifacts]
    -> risk_fusion.fuse_risk()            [decision result only]
    -> controller response                [not automatically connected]
```

The adapter retains monotonic nanoseconds, agent ID and cgroup ID. It maps
`comm` to `process` and the event's `name` to the legacy `path` input.
The latter is not guaranteed to be a complete path for all hook types.

The current BPF event structure does not contain UID. The adapter leaves UID
unset rather than inventing it. UID-related features therefore remain zero.

## Minimal offline example

```python
from detection.event_adapter import normalize_bpf_events
from detection.behavior_features import extract_from_events

normalized = normalize_bpf_events(json_events)
features = extract_from_events(normalized)
```

This demonstrates schema compatibility only. It is not a daemon consuming the
ring buffer continuously, does not prove model quality, and does not change
kernel policy. The controller remains the only component allowed to execute
explicit response actions.
