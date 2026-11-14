#!/usr/bin/env python3

"""
KernelGuard Behavioral Feature Extraction

This module contains the exact 23 behavioral features used by
the validated KernelGuard ML experiments.

Important:
Do not change the feature definitions without retraining the model.
"""

import numpy as np
import pandas as pd


FEATURE_NAMES = [
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
    "path_diversity",
]


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


def dataframe_from_events(events):
    """
    Convert a list of KernelGuard event dictionaries into
    a pandas DataFrame.

    Expected fields include:
        pid
        uid
        process
        path
        timestamp_start
        timestamp_end
    """

    return pd.DataFrame(events)


def extract_from_events(events):
    """
    Extract the 23 behavioral features from a list of events.
    """

    if not events:
        return {
            name: 0.0
            for name in FEATURE_NAMES
        }

    df = dataframe_from_events(events)

    # Ensure timestamps have the correct datetime type.
    for column in [
        "timestamp_start",
        "timestamp_end"
    ]:
        if column in df.columns:
            df[column] = pd.to_datetime(
                df[column],
                errors="coerce"
            )

    return extract_features(df)
