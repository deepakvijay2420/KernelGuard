# KernelGuard ML v2 Dataset

This directory documents the controlled behavioural dataset used in the KernelGuard ML experiments. It explains how the event records were generated, labelled, converted into run-level samples, and used for feature extraction.

> **Scope and reproducibility note:** the generator scripts in this directory collect events from the legacy KernelGuard live log at `~/kernelguard/logs/kernelguard_live.log`. That log format is the v1-style userspace event format (`PID | UID | PROCESS | PATH | RISK | REASON | ACTION`). Therefore, this dataset should be described as a controlled dataset collected using the earlier KernelGuard monitoring pipeline. It is not evidence that the same dataset was captured from the ZTA v2 cgroup/BPF-LSM telemetry path. A separate v2-native dataset collection and schema alignment are future validation tasks.

## 1. Dataset objective

The dataset was created to explore whether execution behaviour can help distinguish normal workloads from controlled suspicious/attack-like workloads.

It is a **research-generated, controlled dataset**, not a public benchmark and not a collection of real-world malware. The attack scenarios use harmless commands and test executables; the suspiciousness is represented by the chosen command sequence and its assigned scenario label.

## 2. Dataset composition

The project README records the following generated dataset totals:

| Class | Runs | Events |
|---|---:|---:|
| Benign | 800 | 1,971 |
| Attack-like | 300 | 810 |
| **Total** | **1,100** | **2,781** |

The 800 benign runs are made from two collections:

- 40 simple benign task types × 10 repetitions = 400 runs.
- 20 composite benign workflow types × 20 repetitions = 400 runs.

The attack-like collection contains:

- 10 controlled attack-like workflow types × 30 repetitions = 300 runs.

These are the planned run counts in the generator scripts. Event totals depend on which matching events the monitor records during each run; use the generated CSV files and their actual row counts as the final authority if the dataset is regenerated.

## 3. How we created the dataset

The generators follow the same broad procedure:

1. Prepare harmless files in `/tmp/kernelguard-ml-lab`.
2. Define a list of command-based workloads.
3. Record the current end offset of the KernelGuard live log.
4. Record the workload start time.
5. Execute the commands for one workload, with command timeouts.
6. Wait briefly for the monitor to write its events.
7. Read only the new log lines after the saved offset.
8. Parse matching event records into fields such as PID, UID, process name, executable path, risk, reason and action.
9. Keep events belonging to the generator's controlled command vocabulary.
10. Attach a run ID, scenario/task ID, repetition number, class label and run timestamps.
11. Save event-level records and run-level metadata as CSV files.

The scripts use log-file offsets so that earlier log entries are not intentionally re-collected as part of the current workload.

### Data collection flow

```text
Controlled workload definition
           |
           v
Harmless files and test commands
           |
           v
Execute one task / workflow
           |
           v
KernelGuard live event log
           |
           v
Read only newly appended log lines
           |
           v
Parse and filter matching events
           |
           v
Attach run ID + scenario + label
           |
           +----------------------+
           |                      |
           v                      v
      Event-level CSV        Run metadata CSV
           |                      |
           +----------+-----------+
                      |
                      v
             Feature extraction
                      |
                      v
             Run-level ML samples
```

## 4. Benign workload generation

### Simple benign tasks

Script: `generators/collect_benign_dataset.py`

The script defines 40 ordinary task types and executes each 10 times. Examples include:

- listing files and reading controlled text files
- searching, sorting, counting and filtering text
- checking file types, metadata and hashes
- creating, copying, moving and removing temporary test files
- checking system information such as date, hostname, uptime and disk usage
- running harmless utility commands

It writes:

- `benign/benign_events.csv` — event-level observations
- `benign/benign_runs.csv` — one metadata row per workload run

### Composite benign workflows

Script: `generators/collect_composite_benign.py`

The script defines 20 multi-command benign workflows and repeats each 20 times. These represent longer sequences, such as controlled file operations, multi-file reads, integrity checks, and research-file analysis.

It writes:

- `benign/benign_composite_events.csv`
- `benign/benign_composite_runs.csv`

Composite workloads are useful because normal agent activity is not always a single command; it may be a sequence of legitimate operations.

## 5. Attack-like workload generation

Script: `generators/collect_attack_dataset.py`

The script defines 10 controlled attack-like workflow categories and repeats each 30 times. The categories in the generator include:

- `prompt_injection_sudo`
- `prompt_injection_bash`
- `shell_execution_chain`
- `password_utility`
- `tmp_executable`
- `unknown_executable`
- `benign_to_sudo`
- `benign_to_shell`
- `repeated_sudo`
- `repeated_shell`

The generator creates harmless test executables under `/tmp` by copying `/bin/echo` and `/bin/true`. It also uses non-interactive or help/test arguments for utility scenarios. The intent is to create observable execution patterns without carrying out destructive actions.

It writes:

- `attacks/attack_events.csv`
- `attacks/attack_runs.csv`

**Important interpretation:** these are labelled attack-like command-sequence simulations. The generator directly executes the listed commands; the category name `prompt_injection_*` does not by itself mean that a live LLM was prompted, that a real malicious document was processed, or that an autonomous agent independently chose the command. Do not describe these rows as real prompt-injection incidents. A separate agent-driven prompt-injection experiment is needed to make that claim.

## 6. Labels and data fields

The generators assign the class label from the workload definition:

- `benign` for the benign task and composite benign workflow generators
- `attack` for the attack-like workflow generator

Each event record includes fields such as:

- `run_id`: unique workload-run identifier
- `task_id`, `workflow_id` or `attack_id`: scenario identifier
- `repetition`: repetition number
- `label`: class assigned by the generator
- `pid`, `uid`: process and user identifiers recorded by the monitor
- `process`, `path`: process name and executable path
- `risk`, `reason`, `action`: fields from the legacy monitor log
- `timestamp_start`, `timestamp_end`: workload-level time boundaries

Run metadata CSVs store the run ID, scenario ID, repetition, label, number of collected events and workload duration.

The label is assigned from the scenario the script intentionally ran. It is not an independent human adjudication of a real-world attack.

## 7. Feature extraction

The behavioural feature implementation is `../../model/behavior_features.py`.

It aggregates the events belonging to a workload run into 23 numerical features:

1. `event_count`
2. `unique_processes`
3. `process_changes`
4. `unique_paths`
5. `mean_path_depth`
6. `max_path_depth`
7. `dominant_path_ratio`
8. `repetition_ratio`
9. `sequence_entropy`
10. `unique_pids`
11. `unique_uids`
12. `uid_changes`
13. `duration`
14. `event_rate`
15. `mean_delta`
16. `max_delta`
17. `std_delta`
18. `burst_count`
19. `bin_path_ratio`
20. `usr_path_ratio`
21. `tmp_path_ratio`
22. `sbin_path_ratio`
23. `path_diversity`

In simple terms, these features describe how many events occurred, how varied the processes and paths were, how often processes changed or repeated, and how quickly events occurred.

The feature extractor uses process/path/timing information. The project README describes a strict behavioural experiment that excludes direct policy-derived fields such as `risk`, `reason`, `action`, task/attack IDs and labels from the model feature inputs. Preserve that separation when reproducing the experiment; labels are targets, not input features.

## 8. Re-running the collection scripts

Run these only in the intended research VM where the matching KernelGuard logging service is already configured and writing the expected legacy log format.

From the repository root:

```bash
python3 dataset/ml_v2/generators/collect_benign_dataset.py
python3 dataset/ml_v2/generators/collect_composite_benign.py
python3 dataset/ml_v2/generators/collect_attack_dataset.py
```

Before running:

- Confirm the monitor is active and writing `~/kernelguard/logs/kernelguard_live.log`.
- Confirm the log format matches the parser regular expression in the selected generator.
- Back up existing CSV outputs; the scripts open output files in write mode and replace previous generated CSVs.
- Do not run multiple generators concurrently against the same log file.
- Inspect the CSV row counts, labels, run IDs, and event counts after generation.
- Record the kernel version, monitor version, policy/configuration, date, and generator commit used for each experiment.

The scripts execute controlled commands on the host. Use a disposable VM and inspect the command lists before running them.

## 9. Limitations and threats to validity

- The dataset is generated from a controlled set of command workflows, so it may not represent the full diversity of real users, agents, Linux distributions or production workloads.
- Labels are inherited from the scenario definitions. A suspicious-looking command sequence is not necessarily malicious in every context.
- The attack-like generator is a deterministic command-sequence simulation; it does not independently demonstrate live LLM prompt-injection behaviour.
- The parser depends on the legacy log format and filters events using a predefined command/path vocabulary. Events outside that vocabulary may be excluded.
- The generator records workload-level start/end timestamps for collected events; these are not necessarily precise per-event kernel timestamps.
- Repeated runs of the same small set of templates may create correlations between training and test samples. Split by run/scenario (and preferably hold out scenarios) rather than randomly splitting individual event rows.
- The dataset is not yet a ZTA v2-native dataset. v2 uses a different cgroup-based identity and BPF event pipeline; a dedicated collector and validated mapping are needed before claiming the ML model was trained on v2 telemetry.
- The recorded totals are project-reported counts. Recalculate them from the CSV artifacts for every regenerated dataset and report any differences.

## 10. Reproducibility checklist

- [ ] Save the exact generator scripts and Git commit.
- [ ] Record Linux kernel and KernelGuard monitor version.
- [ ] Record policy and configuration used during collection.
- [ ] Preserve raw log excerpts or an immutable raw-event export.
- [ ] Verify no unrelated processes polluted the collection window.
- [ ] Check missing/duplicate events and class/run counts.
- [ ] Keep all events from a run in the same data split.
- [ ] Keep scenario IDs available for grouped evaluation, but do not pass them as model features.
- [ ] Report precision, recall, F1-score, confusion matrix and class-wise support.
- [ ] Clearly distinguish controlled simulation results from real-world agent attack evaluation.
