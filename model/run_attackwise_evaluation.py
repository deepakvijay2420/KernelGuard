#!/usr/bin/env python3

import os
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
    f1_score
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

OUTPUT_DIR = os.path.join(
    BASE, "results/ml/attackwise"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("KernelGuard - Attack-Wise Behavioral ML Evaluation")
print("=" * 70)

benign = pd.read_csv(BENIGN_FILE)
composite = pd.read_csv(COMPOSITE_FILE)
attack = pd.read_csv(ATTACK_FILE)

print("\nDataset:")
print(f"Benign events    : {len(benign)}")
print(f"Composite events : {len(composite)}")
print(f"Attack events    : {len(attack)}")


# ============================================================
# NORMALIZE
# ============================================================

def normalize(df):

    df = df.copy()

    df["path"] = df["path"].fillna("").astype(str)
    df["process"] = df["process"].fillna("").astype(str)

    df["timestamp_start"] = pd.to_datetime(
        df["timestamp_start"],
        errors="coerce"
    )

    df["timestamp_end"] = pd.to_datetime(
        df["timestamp_end"],
        errors="coerce"
    )

    return df


benign = normalize(benign)
composite = normalize(composite)
attack = normalize(attack)


# ============================================================
# SCENARIO IDENTIFIERS
# ============================================================

benign["scenario"] = (
    "BENIGN_" + benign["task_id"].astype(str)
)

composite["scenario"] = (
    "COMPOSITE_" + composite["workflow_id"].astype(str)
)

attack["scenario"] = (
    "ATTACK_" + attack["attack_id"].astype(str)
)

benign["target"] = 0
composite["target"] = 0
attack["target"] = 1

benign["category"] = "benign"
composite["category"] = "benign"
attack["category"] = attack["attack_id"].astype(str)


data = pd.concat(
    [benign, composite, attack],
    ignore_index=True
)


# ============================================================
# FEATURE FUNCTIONS
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

    counts = pd.Series(
        values
    ).value_counts(
        normalize=True
    )

    return float(
        -np.sum(
            counts * np.log2(counts)
        )
    )


def extract_features(group):

    group = group.copy()

    paths = group["path"].astype(str).tolist()
    processes = group["process"].astype(str).tolist()

    event_count = len(group)

    unique_processes = len(
        set(processes)
    )

    unique_paths = len(
        set(paths)
    )

    process_changes = sum(
        processes[i] != processes[i - 1]
        for i in range(1, len(processes))
    )

    depths = [
        path_depth(p)
        for p in paths
        if p
    ]

    mean_path_depth = (
        np.mean(depths)
        if depths else 0
    )

    max_path_depth = (
        np.max(depths)
        if depths else 0
    )

    if event_count > 0:

        dominant_path_ratio = (
            pd.Series(paths)
            .value_counts()
            .iloc[0]
            / event_count
        )

    else:

        dominant_path_ratio = 0

    repetition_ratio = (
        1 - unique_paths / event_count
        if event_count > 0
        else 0
    )

    seq_entropy = sequence_entropy(paths)

    unique_pids = (
        group["pid"].nunique()
        if "pid" in group.columns
        else 0
    )

    unique_uids = (
        group["uid"].nunique()
        if "uid" in group.columns
        else 0
    )

    if "uid" in group.columns:

        uid_values = (
            group["uid"]
            .astype(str)
        )

        uid_changes = (
            uid_values
            .ne(uid_values.shift())
            .sum() - 1
        )

        uid_changes = max(
            int(uid_changes),
            0
        )

    else:

        uid_changes = 0


    # --------------------------------------------------------
    # Temporal features
    # --------------------------------------------------------

    duration = 0.0
    event_rate = 0.0

    starts = (
        group["timestamp_start"]
        .dropna()
    )

    ends = (
        group["timestamp_end"]
        .dropna()
    )

    if len(starts) > 0 and len(ends) > 0:

        duration = (
            ends.max() - starts.min()
        ).total_seconds()

        if duration > 0:

            event_rate = (
                event_count / duration
            )


    mean_delta = 0.0
    max_delta = 0.0
    std_delta = 0.0
    burst_count = 0

    if len(starts) > 1:

        times = starts.sort_values()

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

            burst_count = int(
                np.sum(deltas <= 1.0)
            )


    # --------------------------------------------------------
    # Coarse path families
    # --------------------------------------------------------

    bin_count = sum(
        p.startswith("/bin/")
        for p in paths
    )

    usr_bin_count = sum(
        p.startswith("/usr/bin/")
        for p in paths
    )

    tmp_count = sum(
        p.startswith("/tmp/")
        for p in paths
    )

    sbin_count = sum(
        p.startswith("/sbin/")
        or p.startswith("/usr/sbin/")
        for p in paths
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


    return {

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
            (
                unique_paths / event_count
                if event_count > 0
                else 0
            )
    }


# ============================================================
# BUILD RUN-LEVEL DATA
# ============================================================

print("\nBuilding run-level features...")

rows = []

for scenario, scenario_group in data.groupby(
    "scenario"
):

    for run_id, run_group in scenario_group.groupby(
        "run_id"
    ):

        features = extract_features(
            run_group
        )

        features["scenario"] = scenario
        features["run_id"] = run_id
        features["target"] = int(
            run_group["target"].iloc[0]
        )

        if scenario.startswith("ATTACK_"):

            features["category"] = (
                run_group["attack_id"]
                .iloc[0]
            )

        else:

            features["category"] = "benign"

        rows.append(features)


feature_df = pd.DataFrame(rows)


# ============================================================
# FEATURES
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
# 5-FOLD SCENARIO-LEVEL PREDICTIONS
# ============================================================

print("\nRunning 5-fold scenario-level evaluation...")

cv = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)


prediction_rows = []


for fold, (train_idx, test_idx) in enumerate(
    cv.split(X, y, groups),
    start=1
):

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    test_meta = feature_df.iloc[
        test_idx
    ].copy()

    for model_name, model in models.items():

        model.fit(
            X_train,
            y_train
        )

        predictions = model.predict(
            X_test
        )

        for i in range(len(test_idx)):

            row = test_meta.iloc[i]

            prediction_rows.append({

                "fold":
                    fold,

                "model":
                    model_name,

                "run_id":
                    row["run_id"],

                "scenario":
                    row["scenario"],

                "category":
                    row["category"],

                "actual":
                    int(y_test.iloc[i]),

                "predicted":
                    int(predictions[i])
            })


predictions_df = pd.DataFrame(
    prediction_rows
)


# ============================================================
# ATTACK-WISE RESULTS
# ============================================================

print("\n")
print("=" * 70)
print("ATTACK-WISE RESULTS")
print("=" * 70)


attack_results = []


attack_categories = sorted(
    predictions_df[
        predictions_df["actual"] == 1
    ]["category"]
    .unique()
)


for model_name in models.keys():

    print("\n")
    print("-" * 70)
    print(model_name)
    print("-" * 70)

    model_predictions = predictions_df[
        predictions_df["model"] == model_name
    ]

    for category in attack_categories:

        subset = model_predictions[
            model_predictions["category"]
            == category
        ]

        actual = subset["actual"]
        predicted = subset["predicted"]

        total = len(subset)

        detected = int(
            (
                (actual == 1)
                &
                (predicted == 1)
            ).sum()
        )

        missed = int(
            (
                (actual == 1)
                &
                (predicted == 0)
            ).sum()
        )

        detection_rate = (
            detected / total
            if total > 0
            else 0
        )

        attack_results.append({

            "model":
                model_name,

            "attack_category":
                category,

            "total_samples":
                total,

            "detected":
                detected,

            "missed":
                missed,

            "detection_rate":
                detection_rate
        })

        print(
            f"{category:<30} "
            f"Detected={detected:<4} "
            f"Missed={missed:<4} "
            f"Detection={detection_rate * 100:6.2f}%"
        )


attack_results_df = pd.DataFrame(
    attack_results
)


# ============================================================
# OVERALL MODEL METRICS FROM ALL CV PREDICTIONS
# ============================================================

print("\n")
print("=" * 70)
print("OVERALL 5-FOLD METRICS")
print("=" * 70)


overall_rows = []


for model_name in models.keys():

    subset = predictions_df[
        predictions_df["model"] == model_name
    ]

    actual = subset["actual"]
    predicted = subset["predicted"]

    accuracy = accuracy_score(
        actual,
        predicted
    )

    precision = precision_score(
        actual,
        predicted,
        zero_division=0
    )

    recall = recall_score(
        actual,
        predicted,
        zero_division=0
    )

    f1 = f1_score(
        actual,
        predicted,
        zero_division=0
    )

    overall_rows.append({

        "model":
            model_name,

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1
    })

    print(
        f"{model_name:<22} "
        f"Accuracy={accuracy:.4f} "
        f"Precision={precision:.4f} "
        f"Recall={recall:.4f} "
        f"F1={f1:.4f}"
    )


overall_df = pd.DataFrame(
    overall_rows
)


# ============================================================
# BENIGN FALSE POSITIVE ANALYSIS
# ============================================================

print("\n")
print("=" * 70)
print("BENIGN FALSE-POSITIVE ANALYSIS")
print("=" * 70)


benign_results = []


for model_name in models.keys():

    subset = predictions_df[
        (predictions_df["model"] == model_name)
        &
        (predictions_df["actual"] == 0)
    ]

    total = len(subset)

    false_positive = int(
        (
            subset["predicted"] == 1
        ).sum()
    )

    fpr = (
        false_positive / total
        if total > 0
        else 0
    )

    benign_results.append({

        "model":
            model_name,

        "benign_samples":
            total,

        "false_positives":
            false_positive,

        "false_positive_rate":
            fpr
    })

    print(
        f"{model_name:<22} "
        f"Benign={total:<4} "
        f"FalsePositives={false_positive:<4} "
        f"FPR={fpr * 100:.2f}%"
    )


benign_df = pd.DataFrame(
    benign_results
)


# ============================================================
# SAVE RESULTS
# ============================================================

predictions_file = os.path.join(
    OUTPUT_DIR,
    "all_cv_predictions.csv"
)

attack_file = os.path.join(
    OUTPUT_DIR,
    "attackwise_results.csv"
)

overall_file = os.path.join(
    OUTPUT_DIR,
    "overall_metrics.csv"
)

benign_file = os.path.join(
    OUTPUT_DIR,
    "benign_false_positive_results.csv"
)


predictions_df.to_csv(
    predictions_file,
    index=False
)

attack_results_df.to_csv(
    attack_file,
    index=False
)

overall_df.to_csv(
    overall_file,
    index=False
)

benign_df.to_csv(
    benign_file,
    index=False
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("FILES SAVED")
print("=" * 70)

print(predictions_file)
print(attack_file)
print(overall_file)
print(benign_file)

print("\n[+] Attack-wise evaluation completed successfully.")
