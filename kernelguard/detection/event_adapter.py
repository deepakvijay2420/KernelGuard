#!/usr/bin/env python3
"""
Normalize KernelGuard BPF ring-buffer JSON events for behavioural analysis.

The C reader emits ts_ns/cgroup_id/agent/hook/verdict/pid/comm/name.
The existing 23-feature extractor expects timestamp_start/process/path/pid/uid.

This adapter deliberately does not invent UID or file paths. The BPF event
schema currently has no UID field, and "name" may be a file name or an
event-specific label. It is mapped to path for compatibility, while callers
should treat it as an observed name until richer kernel telemetry is added.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


class EventSchemaError(ValueError):
    """Raised when a BPF event is missing required or invalid fields."""


def normalize_bpf_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise EventSchemaError("event must be a JSON object")

    required = ("ts_ns", "agent", "hook", "verdict", "pid", "comm", "name")
    missing = [key for key in required if key not in event]
    if missing:
        raise EventSchemaError(f"missing required BPF event fields: {', '.join(missing)}")

    try:
        ts_ns = int(event["ts_ns"])
        agent = int(event["agent"])
        pid = int(event["pid"])
    except (TypeError, ValueError) as exc:
        raise EventSchemaError("ts_ns, agent and pid must be integers") from exc

    if ts_ns < 0 or agent < 0 or pid < 0:
        raise EventSchemaError("ts_ns, agent and pid must be non-negative")

    process = str(event["comm"])
    observed_name = str(event["name"])
    if not process:
        raise EventSchemaError("comm/process must not be empty")

    # BPF ktime is monotonic time since boot, not Unix epoch time. Preserve
    # exact ns and use a relative numeric timestamp for the feature pipeline.
    # Do not convert it to wall-clock UTC without a boot-time correlation.
    timestamp_seconds = ts_ns / 1_000_000_000

    normalized = {
        "timestamp_start": timestamp_seconds,
        "timestamp_end": timestamp_seconds,
        "pid": pid,
        "process": process,
        "path": observed_name,
        "agent": agent,
        "hook": str(event["hook"]),
        "verdict": str(event["verdict"]),
        "cgroup_id": int(event.get("cgroup_id", 0)),
        "uid": None,
        "ts_ns": ts_ns,
    }
    for key in ("ino", "dev", "dst", "port", "family"):
        if key in event:
            normalized[key] = event[key]
    return normalized


def normalize_bpf_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = [normalize_bpf_event(event) for event in events]
    # Keep deterministic chronological order for sequence and timing features.
    return sorted(normalized, key=lambda item: item["ts_ns"])


def feature_input_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Return only fields consumed by behavior_features.extract_from_events.

    UID is omitted because the current BPF event struct does not emit it.
    Timestamp values are numeric monotonic seconds; the feature extractor
    currently parses timestamps as datetimes, so callers should use
    dataframe_from_events plus explicit timestamp conversion in the next
    version, or use adapt_events_for_features() below.
    """
    return normalize_bpf_events(events)


def adapt_events_for_features(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Produce event dicts with UTC datetime placeholders from monotonic time.

    These datetimes are relative-to-boot represented on an epoch origin solely
    to satisfy the current extractor's datetime arithmetic. They are not real
    wall-clock timestamps. Keep ts_ns for accurate correlation.
    """
    from datetime import timedelta

    base = datetime(1970, 1, 1, tzinfo=timezone.utc)
    result = []
    for item in normalize_bpf_events(events):
        relative = base + timedelta(seconds=item["timestamp_start"])
        row = dict(item)
        row["timestamp_start"] = relative
        row["timestamp_end"] = relative
        result.append(row)
    return result
