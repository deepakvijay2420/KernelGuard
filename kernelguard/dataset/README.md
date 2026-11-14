# KernelGuard ML v2 Dataset

This directory documents the controlled behavioural dataset used in the KernelGuard ML experiments. It explains how event records were generated, labelled, converted into run-level samples, and used for feature extraction.

> **Provenance:** this is a controlled research-generated dataset, not a public benchmark or a collection of real-world malware. The collectors read the legacy KernelGuard text log format (`PID | UID | PROCESS | PATH | RISK | REASON | ACTION`). They have not yet been validated against the canonical BPF ring-buffer JSON stream.

## Dataset composition

| Class | Runs | Events |
|---|---:|---:|
| Benign | 800 | 1,971 |
| Attack-like | 300 | 810 |
| **Total** | **1,100** | **2,781** |

Benign runs comprise 40 simple task types × 10 repetitions and 20 composite workflows × 20 repetitions. Attack-like runs comprise 10 scripted scenarios × 30 repetitions.

## Collection procedure

1. Define a controlled workload and prepare harmless lab files.
2. Record the current legacy log offset and workload start time.
3. Execute the commands with timeouts.
4. Read only newly appended log lines.
5. Parse PID, UID, process, executable path, risk, reason and action.
6. Attach run ID, scenario, repetition, label and timestamps.
7. Save event-level and run-level CSV files.

## Attack-like scenario labels

`prompt_injection_sudo`, `prompt_injection_bash`, `shell_execution_chain`, `password_utility`, `tmp_executable`, `unknown_executable`, `benign_to_sudo`, `benign_to_shell`, `repeated_sudo`, and `repeated_shell`.

These labels represent scripted command-sequence simulations. The generators execute the commands directly; they do not establish that a live LLM processed a malicious document and autonomously selected those commands.

## Features

The canonical extractor in `../detection/behavior_features.py` defines 23 run-level features covering event volume, process/path diversity, sequence changes and repetition, UID/PID diversity, timing, burst activity and coarse executable-path families.

The earlier training scripts in `../../research/models/` also include an experiment with a larger 72-feature command/category representation. Do not conflate that earlier feature set with the canonical 23-feature inference wrapper.

## Reproducibility and limitations

- Preserve the raw CSVs and create a new output directory for each regenerated experiment.
- Keep all events from a run together when splitting data; prefer scenario-grouped evaluation.
- Verify parser compatibility and exclude unrelated host activity.
- Recalculate counts from CSVs when regenerating; the table above is the project-reported dataset composition.
- The legacy text-log schema differs from the canonical BPF JSON event schema. A tested adapter is required before claiming this dataset was collected from the canonical BPF-LSM pipeline.
- The dataset is small and synthetic/controlled. It does not establish generalisation to unseen real-world attacks.

See the root [README](../../README.md) and [research assets guide](../../research/README.md) for evaluation interpretation.
