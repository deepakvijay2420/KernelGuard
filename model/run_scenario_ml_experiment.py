#!/usr/bin/env python3

import os
import time
import numpy as np
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)


BASE = os.path.expanduser("~/kernelguard")

BENIGN_FILE = os.path.join(
    BASE, "dataset/ml_v2/benign/benign_events.csv"
)

COMPOSITE_FILE = os.path.join(
    BASE, "dataset/ml_v2/benign/benign_composite_events.csv"
)

ATTACK_FILE = os.path.join(
    BASE, "dataset/ml_v2/attacks/attack_events.csv"
)

RESULT_DIR = os.path.join(BASE, "results/ml_v2")
DATASET_DIR = os.path.join(BASE, "dataset/ml_v2")

os.makedirs(RESULT_DIR, exist_ok=True)


# =========================================================
# LOAD DATA
# =========================================================

print("\n==============================================")
print(" KernelGuard Scenario-Level Behavioral ML")
print("==============================================\n")

benign = pd.read_csv(BENIGN_FILE)
composite = pd.read_csv(COMPOSITE_FILE)
attack = pd.read_csv(ATTACK_FILE)

print("Benign events     :", len(benign))
print("Composite events  :", len(composite))
print("Attack events     :", len(attack))


# =========================================================
# CREATE SCENARIO IDENTIFIER
#
# All repetitions of the same scenario stay together.
# =========================================================

benign["scenario_group"] = (
    "BENIGN_" + benign["task_id"].astype(str)
)

composite["scenario_group"] = (
    "COMPOSITE_" + composite["workflow_id"].astype(str)
)

attack["scenario_group"] = (
    "ATTACK_" + attack["attack_id"].astype(str)
)

benign["label"] = 0
composite["label"] = 0
attack["label"] = 1


# =========================================================
# FEATURE EXTRACTION
#
# Policy-derived fields are NOT used.
#
# Excluded:
# risk
# reason
# action
# task_id
# attack_id
# label
# run_id
# exact executable identity
# =========================================================

def extract_features(df):

    rows = []

    for run_id, g in df.groupby("run_id"):

        g = g.copy()

        if "timestamp_start" in g.columns:
            g["timestamp_start"] = pd.to_datetime(
                g["timestamp_start"],
                errors="coerce"
            )

        g = g.sort_values("timestamp_start")

        if len(g) == 0:
            continue

        event_count = len(g)

        # -------------------------------------------------
        # TEMPORAL FEATURES
        # -------------------------------------------------

        if event_count > 1:

            times = (
                g["timestamp_start"]
                .astype("int64") / 1e9
            )

            deltas = times.diff().dropna().values

            mean_delta = np.mean(deltas)
            std_delta = np.std(deltas)
            min_delta = np.min(deltas)
            max_delta = np.max(deltas)

            burst_count = np.sum(deltas < 1.0)

        else:

            mean_delta = 0
            std_delta = 0
            min_delta = 0
            max_delta = 0
            burst_count = 0


        # -------------------------------------------------
        # PROCESS STRUCTURE
        # -------------------------------------------------

        unique_processes = (
            g["process"].astype(str).nunique()
        )

        process_changes = (
            g["process"]
            .astype(str)
            .ne(
                g["process"].astype(str).shift()
            )
        ).sum()


        # -------------------------------------------------
        # PATH STRUCTURE
        # -------------------------------------------------

        unique_paths = (
            g["path"].astype(str).nunique()
        )

        path_depths = (
            g["path"]
            .astype(str)
            .str.count("/")
        )

        mean_path_depth = path_depths.mean()
        max_path_depth = path_depths.max()


        # -------------------------------------------------
        # REPETITION
        # -------------------------------------------------

        path_counts = (
            g["path"]
            .astype(str)
            .value_counts()
        )

        dominant_ratio = (
            path_counts.iloc[0] / event_count
        )

        repeated_events = (
            event_count - unique_paths
        )

        repetition_ratio = (
            repeated_events / event_count
        )


        # -------------------------------------------------
        # SEQUENCE ENTROPY
        # -------------------------------------------------

        probabilities = (
            path_counts / event_count
        )

        sequence_entropy = -np.sum(
            probabilities *
            np.log2(probabilities + 1e-12)
        )


        # -------------------------------------------------
        # PROCESS / USER STRUCTURE
        # -------------------------------------------------

        unique_pids = (
            g["pid"].nunique()
        )

        unique_uids = (
            g["uid"].nunique()
        )

        uid_changes = (
            g["uid"]
            .astype(str)
            .ne(
                g["uid"].astype(str).shift()
            )
        ).sum()


        # -------------------------------------------------
        # EXECUTION RATE
        # -------------------------------------------------

        if event_count > 1:

            duration = (
                g["timestamp_start"].iloc[-1]
                -
                g["timestamp_start"].iloc[0]
            ).total_seconds()

            if duration > 0:
                event_rate = (
                    event_count / duration
                )
            else:
                event_rate = event_count

        else:

            duration = 0
            event_rate = event_count


        # -------------------------------------------------
        # COARSE PATH CHARACTERISTICS
        #
        # No exact command identity is used.
        # -------------------------------------------------

        absolute_path_ratio = (
            g["path"]
            .astype(str)
            .str.startswith("/")
            .mean()
        )

        tmp_path_ratio = (
            g["path"]
            .astype(str)
            .str.startswith("/tmp/")
            .mean()
        )

        usr_path_ratio = (
            g["path"]
            .astype(str)
            .str.startswith("/usr/")
            .mean()
        )

        bin_path_ratio = (
            g["path"]
            .astype(str)
            .str.startswith("/bin/")
            .mean()
        )


        rows.append({

            "run_id": run_id,

            "event_count": event_count,

            "unique_processes": unique_processes,
            "process_changes": process_changes,

            "unique_paths": unique_paths,

            "mean_path_depth": mean_path_depth,
            "max_path_depth": max_path_depth,

            "dominant_path_ratio": dominant_ratio,
            "repetition_ratio": repetition_ratio,

            "sequence_entropy": sequence_entropy,

            "unique_pids": unique_pids,
            "unique_uids": unique_uids,
            "uid_changes": uid_changes,

            "duration_seconds": duration,
            "event_rate": event_rate,

            "mean_delta": mean_delta,
            "std_delta": std_delta,
            "min_delta": min_delta,
            "max_delta": max_delta,

            "burst_count": burst_count,

            "absolute_path_ratio": absolute_path_ratio,
            "tmp_path_ratio": tmp_path_ratio,
            "usr_path_ratio": usr_path_ratio,
            "bin_path_ratio": bin_path_ratio,

            "label": int(g["label"].iloc[0]),

            "scenario_group": g[
                "scenario_group"
            ].iloc[0]
        })

    return pd.DataFrame(rows)


# =========================================================
# BUILD FEATURES
# =========================================================

print("\nBuilding run-level behavioral features...")

benign_features = extract_features(benign)
composite_features = extract_features(composite)
attack_features = extract_features(attack)

features = pd.concat(
    [
        benign_features,
        composite_features,
        attack_features
    ],
    ignore_index=True
)

print("\nRun-level samples :", len(features))
print(
    "Behavioral features:",
    len(
        [
            c for c in features.columns
            if c not in [
                "run_id",
                "scenario_group",
                "label"
            ]
        ]
    )
)

print("\nClass distribution:")
print(
    features["label"]
    .map({
        0: "Benign",
        1: "Attack"
    })
    .value_counts()
)

print("\nScenario groups:")
print(
    features["scenario_group"]
    .nunique()
)


# =========================================================
# SAVE FEATURE DATASET
# =========================================================

feature_file = os.path.join(
    DATASET_DIR,
    "scenario_behavior_features.csv"
)

features.to_csv(
    feature_file,
    index=False
)

print("\nSaved:")
print(feature_file)


# =========================================================
# PREPARE ML DATA
# =========================================================

X = features.drop(
    columns=[
        "run_id",
        "scenario_group",
        "label"
    ]
)

y = features["label"]

groups = features["scenario_group"]


# =========================================================
# SCENARIO-LEVEL TRAIN / TEST SPLIT
# =========================================================

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=groups
    )
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

train_groups = set(
    groups.iloc[train_idx]
)

test_groups = set(
    groups.iloc[test_idx]
)


print("\n==============================================")
print(" SCENARIO-LEVEL TRAIN / TEST")
print("==============================================")

print("Training samples :", len(X_train))
print("Testing samples  :", len(X_test))

print("Training scenarios:", len(train_groups))
print("Testing scenarios :", len(test_groups))

overlap = train_groups.intersection(
    test_groups
)

print("Scenario overlap :", len(overlap))

if overlap:
    print("\nERROR: Scenario leakage detected!")
    for item in overlap:
        print(item)
    raise RuntimeError(
        "Scenario groups overlap."
    )

print(
    "PASS: No scenario leakage detected."
)


# =========================================================
# SHOW TRAIN / TEST SCENARIOS
# =========================================================

print("\nTraining scenarios:")

for item in sorted(train_groups):
    print("  ", item)

print("\nTesting scenarios:")

for item in sorted(test_groups):
    print("  ", item)


# =========================================================
# MODELS
# =========================================================

models = {

    "Logistic Regression": Pipeline([
        (
            "scaler",
            StandardScaler()
        ),
        (
            "model",
            LogisticRegression(
                max_iter=2000,
                random_state=42
            )
        )
    ]),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    ),

    "Gradient Boosting": GradientBoostingClassifier(
        random_state=42
    )
}


results = []


# =========================================================
# TRAIN AND EVALUATE
# =========================================================

for name, model in models.items():

    print("\n----------------------------------------------")
    print(name)
    print("----------------------------------------------")

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train
    )

    train_time = (
        time.perf_counter() - start
    )

    start = time.perf_counter()

    predictions = model.predict(
        X_test
    )

    inference_time = (
        time.perf_counter() - start
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ).ravel()

    fpr = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0
    )

    avg_inference_ms = (
        inference_time /
        len(X_test)
    ) * 1000


    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print(
        f"FPR       : {fpr:.4f}"
    )

    print(
        f"Train time: {train_time:.4f} sec"
    )

    print(
        f"Avg inference: "
        f"{avg_inference_ms:.4f} ms/sample"
    )

    print("\nConfusion Matrix:")

    print("TN:", tn)
    print("FP:", fp)
    print("FN:", fn)
    print("TP:", tp)


    results.append({

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
        "avg_inference_ms": avg_inference_ms
    })


# =========================================================
# RESULTS TABLE
# =========================================================

results_df = pd.DataFrame(
    results
)

results_df = results_df.sort_values(
    by=[
        "f1",
        "recall",
        "fpr"
    ],
    ascending=[
        False,
        False,
        True
    ]
)


result_file = os.path.join(
    RESULT_DIR,
    "scenario_behavior_model_comparison.csv"
)

results_df.to_csv(
    result_file,
    index=False
)


# =========================================================
# FEATURE IMPORTANCE
# =========================================================

rf_model = models["Random Forest"]

importance = pd.DataFrame({

    "feature": X.columns,

    "importance":
        rf_model.feature_importances_

})

importance = importance.sort_values(
    "importance",
    ascending=False
)

importance_file = os.path.join(
    RESULT_DIR,
    "random_forest_feature_importance.csv"
)

importance.to_csv(
    importance_file,
    index=False
)


# =========================================================
# FINAL REPORT
# =========================================================

best = results_df.iloc[0]

report_file = os.path.join(
    RESULT_DIR,
    "scenario_behavior_ml_report.txt"
)

with open(report_file, "w") as f:

    f.write(
        "KernelGuard Scenario-Level Behavioral ML Evaluation\n"
    )

    f.write(
        "===================================================\n\n"
    )

    f.write(
        "Purpose:\n"
        "Evaluate whether behavioral and temporal telemetry "
        "can distinguish benign and attack scenarios while "
        "preventing repetitions of the same scenario from "
        "appearing in both training and testing.\n\n"
    )

    f.write(
        "Excluded information:\n"
        "- risk\n"
        "- reason\n"
        "- action\n"
        "- task_id\n"
        "- attack_id\n"
        "- label\n"
        "- exact executable identity\n\n"
    )

    f.write(
        "Evaluation:\n"
        "Scenario-level GroupShuffleSplit was used.\n"
        "All repetitions belonging to the same scenario "
        "were kept in the same partition.\n\n"
    )

    f.write(
        results_df.to_string(
            index=False
        )
    )

    f.write(
        "\n\nBest model: "
        + str(best["model"])
        + "\n"
    )

    f.write(
        "\nImportant limitation:\n"
        "This is a controlled experimental dataset. "
        "The result demonstrates performance on the "
        "generated scenarios and does not establish "
        "generalization to all real-world Agentic AI "
        "attacks.\n"
    )


# =========================================================
# FINAL OUTPUT
# =========================================================

print("\n==============================================")
print(" FINAL SCENARIO-LEVEL RESULTS")
print("==============================================")

print(
    results_df[
        [
            "model",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "fpr",
            "avg_inference_ms"
        ]
    ].to_string(index=False)
)

print(
    "\nBest model:",
    best["model"]
)

print("\nTop Random Forest behavioral features:")

print(
    importance.head(10).to_string(
        index=False
    )
)

print("\nSaved:")
print(result_file)
print(importance_file)
print(report_file)

print("\n==============================================")
print(" Scenario-level experiment completed.")
print("==============================================\n")
