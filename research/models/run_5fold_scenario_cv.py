#!/usr/bin/env python3

import os
import time
import numpy as np
import pandas as pd

from sklearn.model_selection import StratifiedGroupKFold
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


# ============================================================
# CONFIGURATION
# ============================================================

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

OUTPUT_DIR = os.path.join(
    BASE, "results/ml/5fold"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("KernelGuard - 5-Fold Scenario-Level Behavioral ML Validation")
print("=" * 70)

print("\n[1] Loading datasets...")

benign = pd.read_csv(BENIGN_FILE)
composite = pd.read_csv(COMPOSITE_FILE)
attack = pd.read_csv(ATTACK_FILE)

print(f"Benign events     : {len(benign)}")
print(f"Composite events  : {len(composite)}")
print(f"Attack events     : {len(attack)}")


# ============================================================
# NORMALIZE COLUMNS
# ============================================================

def normalize(df):
    df = df.copy()

    df["path"] = df["path"].fillna("").astype(str)
    df["process"] = df["process"].fillna("").astype(str)

    if "timestamp_start" in df.columns:
        df["timestamp_start"] = pd.to_datetime(
            df["timestamp_start"],
            errors="coerce"
        )

    if "timestamp_end" in df.columns:
        df["timestamp_end"] = pd.to_datetime(
            df["timestamp_end"],
            errors="coerce"
        )

    return df


benign = normalize(benign)
composite = normalize(composite)
attack = normalize(attack)


# ============================================================
# CREATE SCENARIO IDENTIFIER
# ============================================================

# IMPORTANT:
# Every repetition belonging to the same scenario receives
# the same scenario group.
#
# This prevents repetitions of one attack from appearing
# in both training and testing folds.

benign["scenario"] = "BENIGN_" + benign["task_id"].astype(str)

composite["scenario"] = (
    "COMPOSITE_" + composite["workflow_id"].astype(str)
)

attack["scenario"] = (
    "ATTACK_" + attack["attack_id"].astype(str)
)


# ============================================================
# LABELS
# ============================================================

benign["target"] = 0
composite["target"] = 0
attack["target"] = 1


data = pd.concat(
    [benign, composite, attack],
    ignore_index=True
)


print("\n[2] Dataset summary")
print("-" * 70)

print(f"Total events       : {len(data)}")
print(f"Benign events      : {(data['target'] == 0).sum()}")
print(f"Attack events      : {(data['target'] == 1).sum()}")

print(f"Unique scenarios   : {data['scenario'].nunique()}")


# ============================================================
# BEHAVIORAL FEATURE EXTRACTION
# ============================================================

def path_depth(path):
    if not path:
        return 0

    return len(
        [x for x in path.split("/") if x]
    )


def sequence_entropy(values):

    if len(values) == 0:
        return 0.0

    counts = pd.Series(values).value_counts(normalize=True)

    entropy = -np.sum(
        counts * np.log2(counts)
    )

    return float(entropy)


def extract_features(group):

    group = group.copy()

    paths = group["path"].astype(str).tolist()
    processes = group["process"].astype(str).tolist()

    event_count = len(group)

    unique_processes = len(set(processes))
    unique_paths = len(set(paths))

    process_changes = 0

    for i in range(1, len(processes)):
        if processes[i] != processes[i - 1]:
            process_changes += 1

    depths = [
        path_depth(p)
        for p in paths
        if p
    ]

    if depths:
        mean_path_depth = np.mean(depths)
        max_path_depth = np.max(depths)
    else:
        mean_path_depth = 0
        max_path_depth = 0

    if event_count > 0:
        dominant_path_ratio = (
            pd.Series(paths).value_counts().iloc[0]
            / event_count
        )
    else:
        dominant_path_ratio = 0

    if event_count > 1:
        repetition_ratio = (
            1 -
            (unique_paths / event_count)
        )
    else:
        repetition_ratio = 0

    seq_entropy = sequence_entropy(paths)

    if "pid" in group.columns:
        unique_pids = group["pid"].nunique()
    else:
        unique_pids = 0

    if "uid" in group.columns:
        unique_uids = group["uid"].nunique()
        uid_changes = (
            group["uid"]
            .astype(str)
            .ne(
                group["uid"]
                .astype(str)
                .shift()
            )
            .sum()
            - 1
        )
        uid_changes = max(uid_changes, 0)
    else:
        unique_uids = 0
        uid_changes = 0

    # --------------------------------------------------------
    # Temporal features
    # --------------------------------------------------------

    duration = 0.0
    event_rate = 0.0

    if (
        "timestamp_start" in group.columns
        and "timestamp_end" in group.columns
    ):

        starts = group["timestamp_start"].dropna()
        ends = group["timestamp_end"].dropna()

        if len(starts) > 0 and len(ends) > 0:

            start_time = starts.min()
            end_time = ends.max()

            duration = (
                end_time - start_time
            ).total_seconds()

            if duration > 0:
                event_rate = (
                    event_count / duration
                )

    # --------------------------------------------------------
    # Inter-event timing
    # --------------------------------------------------------

    mean_delta = 0.0
    max_delta = 0.0
    std_delta = 0.0
    burst_count = 0

    if "timestamp_start" in group.columns:

        times = (
            group["timestamp_start"]
            .dropna()
            .sort_values()
        )

        if len(times) > 1:

            deltas = (
                times.diff()
                .dt.total_seconds()
                .dropna()
                .values
            )

            if len(deltas) > 0:

                mean_delta = float(
                    np.mean(deltas)
                )

                max_delta = float(
                    np.max(deltas)
                )

                std_delta = float(
                    np.std(deltas)
                )

                # Events separated by <= 1 second
                burst_count = int(
                    np.sum(deltas <= 1.0)
                )

    # --------------------------------------------------------
    # Coarse path families
    #
    # IMPORTANT:
    # These are behavioral categories, not exact executable
    # identities.
    # --------------------------------------------------------

    bin_count = sum(
        1 for p in paths
        if p.startswith("/bin/")
    )

    usr_bin_count = sum(
        1 for p in paths
        if p.startswith("/usr/bin/")
    )

    tmp_count = sum(
        1 for p in paths
        if p.startswith("/tmp/")
    )

    sbin_count = sum(
        1 for p in paths
        if p.startswith("/sbin/")
        or p.startswith("/usr/sbin/")
    )

    if event_count > 0:

        bin_path_ratio = (
            bin_count / event_count
        )

        usr_path_ratio = (
            usr_bin_count / event_count
        )

        tmp_path_ratio = (
            tmp_count / event_count
        )

        sbin_path_ratio = (
            sbin_count / event_count
        )

    else:

        bin_path_ratio = 0
        usr_path_ratio = 0
        tmp_path_ratio = 0
        sbin_path_ratio = 0

    # --------------------------------------------------------
    # Final 23 behavioral features
    # --------------------------------------------------------

    features = {

        "event_count":
            event_count,

        "unique_processes":
            unique_processes,

        "process_changes":
            process_changes,

        "unique_paths":
            unique_paths,

        "mean_path_depth":
            mean_path_depth,

        "max_path_depth":
            max_path_depth,

        "dominant_path_ratio":
            dominant_path_ratio,

        "repetition_ratio":
            repetition_ratio,

        "sequence_entropy":
            seq_entropy,

        "unique_pids":
            unique_pids,

        "unique_uids":
            unique_uids,

        "uid_changes":
            uid_changes,

        "duration":
            duration,

        "event_rate":
            event_rate,

        "mean_delta":
            mean_delta,

        "max_delta":
            max_delta,

        "std_delta":
            std_delta,

        "burst_count":
            burst_count,

        "bin_path_ratio":
            bin_path_ratio,

        "usr_path_ratio":
            usr_path_ratio,

        "tmp_path_ratio":
            tmp_path_ratio,

        "sbin_path_ratio":
            sbin_path_ratio,

        "path_diversity":
            unique_paths / event_count
            if event_count > 0 else 0
    }

    return features


# ============================================================
# BUILD RUN-LEVEL DATA
# ============================================================

print("\n[3] Building run-level behavioral features...")

rows = []

for scenario, scenario_group in data.groupby("scenario"):

    # Each repetition/run is kept as an individual sample.
    # The scenario itself becomes the GROUP used for CV.

    if "run_id" not in scenario_group.columns:
        raise RuntimeError(
            "run_id column missing from dataset."
        )

    for run_id, run_group in scenario_group.groupby("run_id"):

        features = extract_features(run_group)

        features["scenario"] = scenario
        features["run_id"] = run_id
        features["target"] = int(
            run_group["target"].iloc[0]
        )

        rows.append(features)


feature_df = pd.DataFrame(rows)


print(
    f"Run-level samples : {len(feature_df)}"
)

print(
    f"Scenario groups   : "
    f"{feature_df['scenario'].nunique()}"
)

print(
    "\nClass distribution:"
)

print(
    feature_df["target"]
    .value_counts()
    .rename({
        0: "Benign",
        1: "Attack"
    })
)


# ============================================================
# FEATURE LIST
# ============================================================

FEATURES = [

    "event_count",
    "unique_processes",
    "process_changes",
    "unique_paths",
    "mean_path_depth",
    "max_path_depth",
    "dominant_path_ratio",
    "repetition_ratio",
    "sequence_entropy",
    "unique_pids",
    "unique_uids",
    "uid_changes",
    "duration",
    "event_rate",
    "mean_delta",
    "max_delta",
    "std_delta",
    "burst_count",
    "bin_path_ratio",
    "usr_path_ratio",
    "tmp_path_ratio",
    "sbin_path_ratio",
    "path_diversity"
]


X = feature_df[FEATURES].fillna(0)

y = feature_df["target"]

groups = feature_df["scenario"]


# ============================================================
# MODELS
# ============================================================

models = {

    "Logistic Regression":
        Pipeline([
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

    "Random Forest":
        RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        ),

    "Gradient Boosting":
        GradientBoostingClassifier(
            random_state=42
        )
}


# ============================================================
# 5-FOLD STRATIFIED GROUP CV
# ============================================================

print("\n[4] Starting 5-fold scenario-level validation...")
print("-" * 70)

cv = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)


all_results = []

model_summary = {name: [] for name in models}


for fold, (train_idx, test_idx) in enumerate(
    cv.split(X, y, groups),
    start=1
):

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    train_groups = groups.iloc[train_idx]
    test_groups = groups.iloc[test_idx]

    overlap = (
        set(train_groups)
        .intersection(set(test_groups))
    )

    print(
        f"\nFold {fold}"
    )

    print(
        f"Training samples : {len(train_idx)}"
    )

    print(
        f"Testing samples  : {len(test_idx)}"
    )

    print(
        f"Training scenarios: "
        f"{train_groups.nunique()}"
    )

    print(
        f"Testing scenarios : "
        f"{test_groups.nunique()}"
    )

    print(
        f"Scenario overlap : {len(overlap)}"
    )

    if len(overlap) != 0:
        raise RuntimeError(
            "DATA LEAKAGE DETECTED!"
        )

    for model_name, model in models.items():

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

        result = {

            "fold": fold,

            "model": model_name,

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

            "avg_inference_ms":
                avg_inference_ms,

            "train_scenarios":
                train_groups.nunique(),

            "test_scenarios":
                test_groups.nunique()
        }

        all_results.append(result)

        model_summary[model_name].append(
            result
        )

        print(
            f"  {model_name:<22} "
            f"Acc={accuracy:.4f} "
            f"Prec={precision:.4f} "
            f"Recall={recall:.4f} "
            f"F1={f1:.4f} "
            f"FPR={fpr:.4f}"
        )


# ============================================================
# SAVE FOLD RESULTS
# ============================================================

results_df = pd.DataFrame(all_results)

fold_file = os.path.join(
    OUTPUT_DIR,
    "fold_results.csv"
)

results_df.to_csv(
    fold_file,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

summary_rows = []

print("\n")
print("=" * 70)
print("5-FOLD CROSS-VALIDATION SUMMARY")
print("=" * 70)

for model_name, rows in model_summary.items():

    df = pd.DataFrame(rows)

    summary = {

        "model": model_name,

        "accuracy_mean":
            df["accuracy"].mean(),

        "accuracy_std":
            df["accuracy"].std(),

        "precision_mean":
            df["precision"].mean(),

        "precision_std":
            df["precision"].std(),

        "recall_mean":
            df["recall"].mean(),

        "recall_std":
            df["recall"].std(),

        "f1_mean":
            df["f1"].mean(),

        "f1_std":
            df["f1"].std(),

        "fpr_mean":
            df["fpr"].mean(),

        "fpr_std":
            df["fpr"].std(),

        "inference_ms_mean":
            df["avg_inference_ms"].mean(),

        "inference_ms_std":
            df["avg_inference_ms"].std()
    }

    summary_rows.append(summary)

    print(f"\n{model_name}")
    print("-" * 50)

    print(
        f"Accuracy : "
        f"{summary['accuracy_mean']:.4f} "
        f"+/- {summary['accuracy_std']:.4f}"
    )

    print(
        f"Precision: "
        f"{summary['precision_mean']:.4f} "
        f"+/- {summary['precision_std']:.4f}"
    )

    print(
        f"Recall   : "
        f"{summary['recall_mean']:.4f} "
        f"+/- {summary['recall_std']:.4f}"
    )

    print(
        f"F1       : "
        f"{summary['f1_mean']:.4f} "
        f"+/- {summary['f1_std']:.4f}"
    )

    print(
        f"FPR      : "
        f"{summary['fpr_mean']:.4f} "
        f"+/- {summary['fpr_std']:.4f}"
    )

    print(
        f"Inference: "
        f"{summary['inference_ms_mean']:.4f} ms/sample"
    )


summary_df = pd.DataFrame(
    summary_rows
)

summary_file = os.path.join(
    OUTPUT_DIR,
    "model_summary.csv"
)

summary_df.to_csv(
    summary_file,
    index=False
)


# ============================================================
# SAVE FEATURE DATASET
# ============================================================

feature_file = os.path.join(
    OUTPUT_DIR,
    "scenario_behavior_features.csv"
)

feature_df.to_csv(
    feature_file,
    index=False
)


# ============================================================
# FINAL MODEL SELECTION
# ============================================================

best = summary_df.sort_values(
    by=[
        "f1_mean",
        "recall_mean",
        "fpr_mean"
    ],
    ascending=[
        False,
        False,
        True
    ]
).iloc[0]


print("\n")
print("=" * 70)
print("RECOMMENDED MODEL")
print("=" * 70)

print(
    f"Model     : {best['model']}"
)

print(
    f"Accuracy  : {best['accuracy_mean']:.4f} "
    f"+/- {best['accuracy_std']:.4f}"
)

print(
    f"Precision : {best['precision_mean']:.4f}"
)

print(
    f"Recall    : {best['recall_mean']:.4f}"
)

print(
    f"F1        : {best['f1_mean']:.4f}"
)

print(
    f"FPR       : {best['fpr_mean']:.4f}"
)

print(
    f"Inference : "
    f"{best['inference_ms_mean']:.4f} ms/sample"
)

print("\nFiles saved:")
print(f"  {fold_file}")
print(f"  {summary_file}")
print(f"  {feature_file}")

print("\n[+] 5-fold validation completed.")
