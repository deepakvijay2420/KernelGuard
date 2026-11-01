#!/usr/bin/env python3

import os
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


# ---------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------

print("\n==============================================")
print(" KernelGuard Strict Behavioral ML Experiment")
print("==============================================\n")

benign = pd.read_csv(BENIGN_FILE)
composite = pd.read_csv(COMPOSITE_FILE)
attack = pd.read_csv(ATTACK_FILE)

benign["source_type"] = "benign"
composite["source_type"] = "composite"
attack["source_type"] = "attack"

print("Benign events     :", len(benign))
print("Composite events  :", len(composite))
print("Attack events     :", len(attack))


# ---------------------------------------------------------
# NORMALIZE RUN ID
# ---------------------------------------------------------

def normalize_run_id(row):
    return str(row["run_id"])


for df in [benign, composite, attack]:
    df["run_id_norm"] = df.apply(normalize_run_id, axis=1)


# ---------------------------------------------------------
# ONLY TELEMETRY / BEHAVIORAL FEATURES
#
# IMPORTANT:
# We deliberately DO NOT use:
#   risk
#   reason
#   action
#   task_id
#   attack_id
#   label
#   run_id
#
# We also do NOT use exact executable names.
# This prevents the model from simply learning:
# "sudo = attack"
# "bash = attack"
# ---------------------------------------------------------


def extract_features(df, label):

    rows = []

    for run_id, g in df.groupby("run_id_norm"):

        g = g.copy()

        if "timestamp_start" in g.columns:
            g["timestamp_start"] = pd.to_datetime(
                g["timestamp_start"],
                errors="coerce"
            )

        g = g.sort_values("timestamp_start")

        event_count = len(g)

        if event_count == 0:
            continue

        # ---------------------------------------------
        # TEMPORAL FEATURES
        # ---------------------------------------------

        if len(g) > 1:
            times = g["timestamp_start"].astype("int64") / 1e9
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


        # ---------------------------------------------
        # STRUCTURAL FEATURES
        # ---------------------------------------------

        unique_processes = g["process"].nunique()

        process_changes = (
            g["process"].astype(str).ne(
                g["process"].astype(str).shift()
            )
        ).sum()

        unique_paths = g["path"].nunique()

        path_depths = (
            g["path"]
            .astype(str)
            .str.count("/")
        )

        mean_path_depth = path_depths.mean()
        max_path_depth = path_depths.max()


        # ---------------------------------------------
        # REPETITION / DIVERSITY
        # ---------------------------------------------

        path_counts = g["path"].astype(str).value_counts()

        if event_count > 0:
            dominant_ratio = (
                path_counts.iloc[0] / event_count
            )
        else:
            dominant_ratio = 0

        repeated_events = (
            event_count - unique_paths
        )

        repetition_ratio = (
            repeated_events / event_count
        )


        # ---------------------------------------------
        # SEQUENCE / ENTROPY FEATURES
        # ---------------------------------------------

        probabilities = (
            path_counts / event_count
        )

        entropy = -np.sum(
            probabilities *
            np.log2(probabilities + 1e-12)
        )


        # ---------------------------------------------
        # PID / USER STRUCTURE
        # ---------------------------------------------

        unique_pids = g["pid"].nunique()

        unique_uids = g["uid"].nunique()

        uid_changes = (
            g["uid"]
            .astype(str)
            .ne(g["uid"].astype(str).shift())
        ).sum()


        # ---------------------------------------------
        # EXECUTION RATE
        # ---------------------------------------------

        if len(g) > 1:

            duration = (
                g["timestamp_start"].iloc[-1]
                - g["timestamp_start"].iloc[0]
            ).total_seconds()

            if duration > 0:
                event_rate = event_count / duration
            else:
                event_rate = event_count

        else:

            duration = 0
            event_rate = event_count


        # ---------------------------------------------
        # COARSE PATH CHARACTERISTICS
        #
        # No exact executable identity.
        # ---------------------------------------------

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


        # ---------------------------------------------
        # BEHAVIORAL FEATURES
        # ---------------------------------------------

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

            "sequence_entropy": entropy,

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

            "label": label
        })

    return pd.DataFrame(rows)


# ---------------------------------------------------------
# BUILD RUN-LEVEL DATASET
# ---------------------------------------------------------

print("\nBuilding behavioral features...")

benign_features = extract_features(
    benign,
    0
)

composite_features = extract_features(
    composite,
    0
)

attack_features = extract_features(
    attack,
    1
)

features = pd.concat(
    [
        benign_features,
        composite_features,
        attack_features
    ],
    ignore_index=True
)

print("\nRun-level samples:", len(features))
print("Feature count    :", len(features.columns) - 2)

print("\nClass distribution:")
print(
    features["label"]
    .map({0: "Benign", 1: "Attack"})
    .value_counts()
)


# ---------------------------------------------------------
# SAVE FEATURES
# ---------------------------------------------------------

feature_file = os.path.join(
    DATASET_DIR,
    "strict_behavior_features.csv"
)

features.to_csv(
    feature_file,
    index=False
)

print("\nSaved:")
print(feature_file)


# ---------------------------------------------------------
# PREPARE ML DATA
# ---------------------------------------------------------

X = features.drop(
    columns=["run_id", "label"]
)

y = features["label"]

groups = features["run_id"]


# ---------------------------------------------------------
# GROUP-AWARE TRAIN / TEST SPLIT
# ---------------------------------------------------------

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
print(" GROUP-AWARE TRAIN / TEST")
print("==============================================")

print("Training samples :", len(X_train))
print("Testing samples  :", len(X_test))

print("Training groups  :", len(train_groups))
print("Testing groups   :", len(test_groups))

print(
    "Group overlap    :",
    len(train_groups.intersection(test_groups))
)

if train_groups.intersection(test_groups):
    raise RuntimeError(
        "DATA LEAKAGE: train/test groups overlap!"
    )

print("PASS: No group leakage detected.")


# ---------------------------------------------------------
# MODELS
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# TRAIN / EVALUATE
# ---------------------------------------------------------

for name, model in models.items():

    print("\n----------------------------------------------")
    print(name)
    print("----------------------------------------------")

    model.fit(
        X_train,
        y_train
    )

    predictions = model.predict(
        X_test
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

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"FPR       : {fpr:.4f}")

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
        "tp": tp
    })


# ---------------------------------------------------------
# RESULTS
# ---------------------------------------------------------

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    by=["f1", "recall", "fpr"],
    ascending=[False, False, True]
)

result_file = os.path.join(
    RESULT_DIR,
    "strict_behavior_model_comparison.csv"
)

results_df.to_csv(
    result_file,
    index=False
)


# ---------------------------------------------------------
# REPORT
# ---------------------------------------------------------

best = results_df.iloc[0]

report_file = os.path.join(
    RESULT_DIR,
    "strict_behavior_ml_report.txt"
)

with open(report_file, "w") as f:

    f.write(
        "KernelGuard Strict Behavioral ML Experiment\n"
    )

    f.write(
        "============================================\n\n"
    )

    f.write(
        "Purpose:\n"
        "Evaluate whether attacks can be distinguished "
        "using policy-independent behavioral and temporal "
        "telemetry.\n\n"
    )

    f.write(
        "Excluded features:\n"
        "- risk\n"
        "- reason\n"
        "- action\n"
        "- task_id\n"
        "- attack_id\n"
        "- label\n"
        "- exact executable identity\n\n"
    )

    f.write(
        "Group-aware train/test split was used to prevent "
        "run-level leakage.\n\n"
    )

    f.write(
        results_df.to_string(
            index=False
        )
    )

    f.write("\n\nBest model:\n")
    f.write(str(best["model"]))

    f.write("\n\nImportant interpretation:\n")

    f.write(
        "These results measure behavioral classification "
        "on the current controlled dataset. They should "
        "not be interpreted as proof of generalization "
        "to unseen real-world attacks.\n"
    )


print("\n==============================================")
print(" FINAL MODEL COMPARISON")
print("==============================================")

print(
    results_df[
        [
            "model",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "fpr"
        ]
    ].to_string(index=False)
)

print("\nBest model:", best["model"])

print("\nSaved:")
print(result_file)
print(report_file)

print("\n==============================================")
print(" Experiment completed successfully.")
print("==============================================\n")
