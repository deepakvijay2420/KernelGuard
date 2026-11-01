#!/usr/bin/env python3

import csv
import json
import math
import time
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# ============================================================
# KernelGuard Behavioral ML Experiment
# ============================================================

BASE = Path.home() / "kernelguard"

BENIGN_FILES = [
    BASE / "dataset/ml_v2/benign/benign_events.csv",
    BASE / "dataset/ml_v2/benign/benign_composite_events.csv",
]

ATTACK_FILE = (
    BASE / "dataset/ml_v2/attacks/attack_events.csv"
)

RESULT_DIR = BASE / "results/ml_v2"
RESULT_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_FILE = (
    BASE / "dataset/ml_v2/run_level_features.csv"
)

MODEL_RESULT_FILE = (
    RESULT_DIR / "model_comparison.csv"
)

REPORT_FILE = (
    RESULT_DIR / "ml_experiment_report.txt"
)

RANDOM_STATE = 42


# ============================================================
# Utility
# ============================================================

def load_csv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def safe_float(value):
    try:
        return float(value)
    except Exception:
        return 0.0


def basename(path):
    return Path(path).name


def command_category(path):
    """
    Coarse behavioral category.
    Does NOT use KernelGuard risk/action.
    """

    name = basename(path)

    file_commands = {
        "ls", "cat", "head", "tail", "grep",
        "wc", "sort", "uniq", "cut", "tr",
        "file", "stat", "du", "find", "awk",
        "sed"
    }

    system_commands = {
        "pwd", "whoami", "id", "uname",
        "hostname", "date", "uptime",
        "free", "df"
    }

    file_operation_commands = {
        "mkdir", "touch", "cp", "mv", "rm",
        "echo", "printf"
    }

    integrity_commands = {
        "sha256sum", "md5sum"
    }

    archive_commands = {
        "tar", "gzip"
    }

    shell_commands = {
        "bash", "sh"
    }

    privileged_commands = {
        "sudo", "passwd"
    }

    if name in file_commands:
        return "file_observation"

    if name in system_commands:
        return "system_information"

    if name in file_operation_commands:
        return "file_operation"

    if name in integrity_commands:
        return "integrity"

    if name in archive_commands:
        return "archive"

    if name in shell_commands:
        return "shell"

    if name in privileged_commands:
        return "privileged"

    if path.startswith("/tmp/"):
        return "tmp_execution"

    return "other"


# ============================================================
# Load raw events
# ============================================================

print()
print("=" * 75)
print(" KernelGuard Behavioral ML Experiment")
print("=" * 75)

print()
print("[1/7] Loading datasets...")

benign_events = []

for file in BENIGN_FILES:
    rows = load_csv(file)

    for row in rows:
        row["_source"] = "benign"

    benign_events.extend(rows)

attack_events = load_csv(ATTACK_FILE)

for row in attack_events:
    row["_source"] = "attack"


events = benign_events + attack_events

print("Benign events :", len(benign_events))
print("Attack events :", len(attack_events))
print("Total events  :", len(events))


# ============================================================
# Group events by run
# ============================================================

print()
print("[2/7] Grouping events into behavioral runs...")

runs = defaultdict(list)

for event in events:
    runs[event["run_id"]].append(event)

print("Total runs:", len(runs))


# ============================================================
# Determine command vocabulary
# ============================================================

command_counter = Counter()

for event in events:
    command_counter[basename(event["path"])] += 1


# Use the complete observed vocabulary.
# Dataset is small enough that this is practical.
COMMANDS = sorted(command_counter.keys())

print("Unique executable names:", len(COMMANDS))

print()
print("Observed commands:")

for command in COMMANDS:
    print(f"  {command}")


# ============================================================
# Feature extraction
# ============================================================

print()
print("[3/7] Extracting run-level behavioral features...")


def extract_features(run_events):

    paths = [
        e["path"]
        for e in run_events
    ]

    commands = [
        basename(p)
        for p in paths
    ]

    categories = [
        command_category(p)
        for p in paths
    ]

    timestamps = sorted(
        safe_float(e["timestamp_start"])
        for e in run_events
    )

    feature = {}

    # --------------------------------------------------------
    # Basic sequence statistics
    # --------------------------------------------------------

    feature["event_count"] = len(run_events)

    feature["unique_command_count"] = len(
        set(commands)
    )

    feature["unique_path_count"] = len(
        set(paths)
    )

    feature["command_diversity"] = (
        len(set(commands)) / max(len(commands), 1)
    )

    # --------------------------------------------------------
    # Temporal features
    # --------------------------------------------------------

    if len(timestamps) > 1:

        deltas = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        feature["mean_time_delta"] = float(
            np.mean(deltas)
        )

        feature["max_time_delta"] = float(
            np.max(deltas)
        )

        feature["min_time_delta"] = float(
            np.min(deltas)
        )

        feature["std_time_delta"] = float(
            np.std(deltas)
        )

        feature["sequence_duration"] = (
            max(timestamps) - min(timestamps)
        )

    else:

        feature["mean_time_delta"] = 0.0
        feature["max_time_delta"] = 0.0
        feature["min_time_delta"] = 0.0
        feature["std_time_delta"] = 0.0
        feature["sequence_duration"] = 0.0

    # --------------------------------------------------------
    # Command frequency features
    # --------------------------------------------------------

    counts = Counter(commands)

    for command in COMMANDS:

        feature[
            f"cmd_{command}"
        ] = counts.get(command, 0)

    # --------------------------------------------------------
    # Behavioral category counts
    # --------------------------------------------------------

    category_counts = Counter(categories)

    for category in [
        "file_observation",
        "system_information",
        "file_operation",
        "integrity",
        "archive",
        "shell",
        "privileged",
        "tmp_execution",
        "other",
    ]:

        feature[
            f"category_{category}"
        ] = category_counts.get(category, 0)

    # --------------------------------------------------------
    # Security-relevant behavioral indicators
    # --------------------------------------------------------

    feature["sudo_count"] = counts.get(
        "sudo", 0
    )

    feature["bash_count"] = counts.get(
        "bash", 0
    )

    feature["sh_count"] = counts.get(
        "sh", 0
    )

    feature["passwd_count"] = counts.get(
        "passwd", 0
    )

    feature["tmp_execution_count"] = sum(
        1
        for p in paths
        if p.startswith("/tmp/")
    )

    feature["shell_count"] = (
        counts.get("bash", 0)
        + counts.get("sh", 0)
    )

    feature["privileged_count"] = (
        counts.get("sudo", 0)
        + counts.get("passwd", 0)
    )

    feature["suspicious_sequence"] = int(
        (
            counts.get("sudo", 0) > 0
            or counts.get("passwd", 0) > 0
            or counts.get("bash", 0) > 0
            or counts.get("sh", 0) > 0
            or any(p.startswith("/tmp/") for p in paths)
        )
    )

    # --------------------------------------------------------
    # Ratios
    # --------------------------------------------------------

    total = max(len(commands), 1)

    feature["sudo_ratio"] = (
        feature["sudo_count"] / total
    )

    feature["shell_ratio"] = (
        feature["shell_count"] / total
    )

    feature["privileged_ratio"] = (
        feature["privileged_count"] / total
    )

    feature["tmp_ratio"] = (
        feature["tmp_execution_count"] / total
    )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    first = run_events[0]

    feature["_run_id"] = first["run_id"]
    feature["_label"] = (
        1 if first["label"] == "attack" else 0
    )

    if first["label"] == "attack":
        feature["_group"] = (
            "attack:" + first.get("attack_id", "unknown")
        )
        feature["_scenario"] = first.get(
            "attack_id", "unknown"
        )
    else:
        scenario = (
            first.get("task_id")
            or first.get("workflow_id")
            or "unknown"
        )

        feature["_group"] = (
            "benign:" + scenario
        )

        feature["_scenario"] = scenario

    return feature


feature_rows = []

for run_id, run_events in runs.items():

    run_events = sorted(
        run_events,
        key=lambda x: safe_float(
            x["timestamp_start"]
        )
    )

    feature_rows.append(
        extract_features(run_events)
    )


print("Run-level samples:", len(feature_rows))


# ============================================================
# Save feature dataset
# ============================================================

print()
print("[4/7] Saving feature dataset...")

metadata_fields = [
    "_run_id",
    "_label",
    "_group",
    "_scenario",
]

feature_names = [
    k
    for k in feature_rows[0].keys()
    if k not in metadata_fields
]

with FEATURE_FILE.open(
    "w",
    newline=""
) as f:

    writer = csv.writer(f)

    writer.writerow(
        metadata_fields + feature_names
    )

    for row in feature_rows:

        writer.writerow(
            [
                row[k]
                for k in metadata_fields
            ]
            +
            [
                row[k]
                for k in feature_names
            ]
        )


print("Saved:")
print(FEATURE_FILE)

print("Number of features:", len(feature_names))


# ============================================================
# Prepare X / y
# ============================================================

X = np.array(
    [
        [
            float(row[f])
            for f in feature_names
        ]
        for row in feature_rows
    ],
    dtype=float
)

y = np.array(
    [
        row["_label"]
        for row in feature_rows
    ],
    dtype=int
)

groups = np.array(
    [
        row["_group"]
        for row in feature_rows
    ]
)


print()
print("Class distribution:")
print("Benign:", int(np.sum(y == 0)))
print("Attack:", int(np.sum(y == 1)))


# ============================================================
# Group-aware train/test split
# ============================================================

print()
print("[5/7] Creating group-aware train/test split...")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.25,
    random_state=RANDOM_STATE
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=groups
    )
)

X_train = X[train_idx]
X_test = X[test_idx]

y_train = y[train_idx]
y_test = y[test_idx]

train_groups = set(
    groups[train_idx]
)

test_groups = set(
    groups[test_idx]
)

print("Training samples:", len(train_idx))
print("Testing samples :", len(test_idx))

print("Training groups :", len(train_groups))
print("Testing groups  :", len(test_groups))

overlap = train_groups.intersection(
    test_groups
)

print("Group overlap   :", len(overlap))

if overlap:
    print()
    print("WARNING: group overlap detected!")

else:
    print()
    print("PASS: no group leakage detected.")


# ============================================================
# Models
# ============================================================

print()
print("[6/7] Training candidate models...")


models = {

    "Logistic Regression": Pipeline(
        [
            (
                "scaler",
                StandardScaler()
            ),

            (
                "model",
                LogisticRegression(
                    max_iter=3000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE
                )
            )
        ]
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    ),

    "Gradient Boosting": GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.05,
        max_depth=3,
        random_state=RANDOM_STATE
    ),
}


results = []

predictions = {}

for name, model in models.items():

    print()
    print("----------------------------------------")
    print(name)
    print("----------------------------------------")

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train
    )

    train_time = (
        time.perf_counter() - start
    )

    start = time.perf_counter()

    prediction = model.predict(
        X_test
    )

    inference_time = (
        time.perf_counter() - start
    )

    predictions[name] = prediction

    accuracy = accuracy_score(
        y_test,
        prediction
    )

    precision = precision_score(
        y_test,
        prediction,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        prediction,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        prediction,
        zero_division=0
    )

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        prediction,
        labels=[0, 1]
    ).ravel()

    fpr = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0
    )

    avg_inference_ms = (
        inference_time
        / len(X_test)
        * 1000
    )

    print(
        f"Accuracy          : {accuracy:.4f}"
    )

    print(
        f"Precision         : {precision:.4f}"
    )

    print(
        f"Recall            : {recall:.4f}"
    )

    print(
        f"F1 Score          : {f1:.4f}"
    )

    print(
        f"False Positive Rate: {fpr:.4f}"
    )

    print(
        f"Train time        : {train_time:.6f} sec"
    )

    print(
        f"Avg inference     : {avg_inference_ms:.6f} ms/sample"
    )

    print()
    print("Confusion Matrix:")
    print(
        f"TN={tn} FP={fp}"
    )
    print(
        f"FN={fn} TP={tp}"
    )

    results.append(
        {
            "model": name,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "train_time_sec": train_time,
            "avg_inference_ms": avg_inference_ms,
        }
    )


# ============================================================
# Save model comparison
# ============================================================

with MODEL_RESULT_FILE.open(
    "w",
    newline=""
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=results[0].keys()
    )

    writer.writeheader()

    writer.writerows(results)


# ============================================================
# Select candidate based on F1
# ============================================================

best = max(
    results,
    key=lambda r: (
        r["f1"],
        r["recall"],
        -r["fpr"]
    )
)


# ============================================================
# Detailed report
# ============================================================

with REPORT_FILE.open("w") as f:

    f.write(
        "KernelGuard Behavioral ML Experiment\n"
    )

    f.write(
        "=====================================\n\n"
    )

    f.write(
        f"Total raw events : {len(events)}\n"
    )

    f.write(
        f"Total run samples: {len(feature_rows)}\n"
    )

    f.write(
        f"Total features   : {len(feature_names)}\n\n"
    )

    f.write(
        f"Training samples : {len(train_idx)}\n"
    )

    f.write(
        f"Testing samples  : {len(test_idx)}\n\n"
    )

    f.write(
        "Models compared:\n"
    )

    for result in results:

        f.write(
            f"\n{result['model']}\n"
        )

        f.write(
            f"  Accuracy : {result['accuracy']:.4f}\n"
        )

        f.write(
            f"  Precision: {result['precision']:.4f}\n"
        )

        f.write(
            f"  Recall   : {result['recall']:.4f}\n"
        )

        f.write(
            f"  F1       : {result['f1']:.4f}\n"
        )

        f.write(
            f"  FPR      : {result['fpr']:.4f}\n"
        )

        f.write(
            f"  Avg inference ms: "
            f"{result['avg_inference_ms']:.6f}\n"
        )

    f.write(
        "\n\nCandidate selected using F1/Recall/FPR:\n"
    )

    f.write(
        best["model"] + "\n"
    )


# ============================================================
# Final output
# ============================================================

print()
print("=" * 75)
print(" ML EXPERIMENT COMPLETE")
print("=" * 75)

print()
print("Feature dataset:")
print(FEATURE_FILE)

print()
print("Model comparison:")
print(MODEL_RESULT_FILE)

print()
print("Experiment report:")
print(REPORT_FILE)

print()
print(
    "Candidate with strongest F1/Recall/FPR trade-off:"
)
print(
    best["model"]
)

print()
print(
    "IMPORTANT: This is a candidate selection result, "
    "not a claim that this model is universally best."
)

print()
print("=" * 75)
