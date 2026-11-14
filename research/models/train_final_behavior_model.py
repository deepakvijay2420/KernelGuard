#!/usr/bin/env python3

import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


# ============================================================
# CONFIGURATION
# ============================================================

BASE = os.path.expanduser("~/kernelguard")

BENIGN_FILE = os.path.join(
    BASE,
    "dataset/ml_v2/benign/benign_events.csv"
)

COMPOSITE_FILE = os.path.join(
    BASE,
    "dataset/ml_v2/benign/benign_composite_events.csv"
)

ATTACK_FILE = os.path.join(
    BASE,
    "dataset/ml_v2/attacks/attack_events.csv"
)

MODEL_FILE = os.path.join(
    BASE,
    "model/random_forest_behavior_model.joblib"
)

FEATURE_FILE = os.path.join(
    BASE,
    "model/behavior_features.joblib"
)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("KernelGuard - Final Behavioral ML Model Training")
print("=" * 70)

print("\n[1] Loading datasets...")

benign = pd.read_csv(BENIGN_FILE)
composite = pd.read_csv(COMPOSITE_FILE)
attack = pd.read_csv(ATTACK_FILE)

print(f"Benign events     : {len(benign)}")
print(f"Composite events  : {len(composite)}")
print(f"Attack events     : {len(attack)}")


# ============================================================
# NORMALIZE
# ============================================================

def normalize(df):

    df = df.copy()

    df["path"] = (
        df["path"]
        .fillna("")
        .astype(str)
    )

    df["process"] = (
        df["process"]
        .fillna("")
        .astype(str)
    )

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
# SCENARIO IDENTIFIERS
# ============================================================

benign["scenario"] = (
    "BENIGN_" +
    benign["task_id"].astype(str)
)

composite["scenario"] = (
    "COMPOSITE_" +
    composite["workflow_id"].astype(str)
)

attack["scenario"] = (
    "ATTACK_" +
    attack["attack_id"].astype(str)
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

print(f"Total events     : {len(data)}")
print(
    f"Benign events    : "
    f"{(data['target'] == 0).sum()}"
)
print(
    f"Attack events    : "
    f"{(data['target'] == 1).sum()}"
)
print(
    f"Scenarios        : "
    f"{data['scenario'].nunique()}"
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

    counts = (
        pd.Series(values)
        .value_counts(normalize=True)
    )

    entropy = -np.sum(
        counts * np.log2(counts)
    )

    return float(entropy)


def extract_features(group):

    group = group.copy()

    paths = (
        group["path"]
        .astype(str)
        .tolist()
    )

    processes = (
        group["process"]
        .astype(str)
        .tolist()
    )

    event_count = len(group)

    unique_processes = len(
        set(processes)
    )

    unique_paths = len(
        set(paths)
    )

    # --------------------------------------------------------
    # Process behaviour
    # --------------------------------------------------------

    process_changes = 0

    for i in range(1, len(processes)):

        if processes[i] != processes[i - 1]:
            process_changes += 1

    # --------------------------------------------------------
    # Path behaviour
    # --------------------------------------------------------

    depths = [
        path_depth(p)
        for p in paths
        if p
    ]

    if depths:

        mean_path_depth = float(
            np.mean(depths)
        )

        max_path_depth = float(
            np.max(depths)
        )

    else:

        mean_path_depth = 0.0
        max_path_depth = 0.0

    if event_count > 0:

        dominant_path_ratio = (
            pd.Series(paths)
            .value_counts()
            .iloc[0]
            / event_count
        )

    else:

        dominant_path_ratio = 0.0

    if event_count > 1:

        repetition_ratio = (
            1 -
            (
                unique_paths /
                event_count
            )
        )

    else:

        repetition_ratio = 0.0

    seq_entropy = sequence_entropy(paths)

    # --------------------------------------------------------
    # Process identity behaviour
    # --------------------------------------------------------

    if "pid" in group.columns:

        unique_pids = (
            group["pid"].nunique()
        )

    else:

        unique_pids = 0

    if "uid" in group.columns:

        unique_uids = (
            group["uid"].nunique()
        )

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

        uid_changes = max(
            uid_changes,
            0
        )

    else:

        unique_uids = 0
        uid_changes = 0

    # --------------------------------------------------------
    # Temporal behaviour
    # --------------------------------------------------------

    duration = 0.0
    event_rate = 0.0

    if (
        "timestamp_start" in group.columns
        and
        "timestamp_end" in group.columns
    ):

        starts = (
            group["timestamp_start"]
            .dropna()
        )

        ends = (
            group["timestamp_end"]
            .dropna()
        )

        if (
            len(starts) > 0
            and
            len(ends) > 0
        ):

            start_time = starts.min()
            end_time = ends.max()

            duration = (
                end_time -
                start_time
            ).total_seconds()

            if duration > 0:

                event_rate = (
                    event_count /
                    duration
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

                burst_count = int(
                    np.sum(
                        deltas <= 1.0
                    )
                )

    # --------------------------------------------------------
    # Coarse path families
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
        if (
            p.startswith("/sbin/")
            or
            p.startswith("/usr/sbin/")
        )
    )

    if event_count > 0:

        bin_path_ratio = (
            bin_count /
            event_count
        )

        usr_path_ratio = (
            usr_bin_count /
            event_count
        )

        tmp_path_ratio = (
            tmp_count /
            event_count
        )

        sbin_path_ratio = (
            sbin_count /
            event_count
        )

    else:

        bin_path_ratio = 0.0
        usr_path_ratio = 0.0
        tmp_path_ratio = 0.0
        sbin_path_ratio = 0.0

    # --------------------------------------------------------
    # EXACT 23 FEATURES
    # --------------------------------------------------------

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
                unique_paths /
                event_count
                if event_count > 0
                else 0.0
            )
    }


# ============================================================
# BUILD RUN-LEVEL SAMPLES
# ============================================================

print("\n[3] Building behavioral features...")
print("-" * 70)

rows = []

for scenario, scenario_group in data.groupby(
    "scenario"
):

    if "run_id" not in scenario_group.columns:

        raise RuntimeError(
            "run_id column missing."
        )

    for run_id, run_group in (
        scenario_group.groupby("run_id")
    ):

        features = extract_features(
            run_group
        )

        features["scenario"] = scenario
        features["run_id"] = run_id

        features["target"] = int(
            run_group["target"].iloc[0]
        )

        rows.append(features)


feature_df = pd.DataFrame(rows)


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


X = (
    feature_df[FEATURES]
    .fillna(0)
)

y = feature_df["target"]


print(f"Run-level samples : {len(X)}")
print(
    f"Number of features: {len(FEATURES)}"
)

print("\nClass distribution:")
print(
    y.value_counts()
    .rename({
        0: "Benign",
        1: "Attack"
    })
)


# ============================================================
# FINAL RANDOM FOREST
# ============================================================

print("\n[4] Training final Random Forest...")
print("-" * 70)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X,
    y
)


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    model,
    MODEL_FILE
)

joblib.dump(
    FEATURES,
    FEATURE_FILE
)


# ============================================================
# MODEL INFORMATION
# ============================================================

print("\n[5] Model information")
print("-" * 70)

print(
    f"Trees              : "
    f"{model.n_estimators}"
)

print(
    f"Features           : "
    f"{len(FEATURES)}"
)

print(
    f"Training samples   : "
    f"{len(X)}"
)

print(
    f"Model saved        : "
    f"{MODEL_FILE}"
)

print(
    f"Feature list saved : "
    f"{FEATURE_FILE}"
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": model.feature_importances_
})

importance = importance.sort_values(
    "importance",
    ascending=False
)

print("\n[6] Top behavioral features")
print("-" * 70)

for _, row in importance.head(10).iterrows():

    print(
        f"{row['feature']:<25} "
        f"{row['importance']:.6f}"
    )


print("\n" + "=" * 70)
print("FINAL MODEL TRAINING COMPLETE")
print("=" * 70)
