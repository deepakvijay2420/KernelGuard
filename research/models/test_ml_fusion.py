#!/usr/bin/env python3

from behavior_ml import BehaviorML
from risk_fusion import fuse_risk


def test_case(name, zta_decision, features):
    print()
    print("=" * 65)
    print(name)
    print("=" * 65)

    ml = BehaviorML()

    result = ml.predict(features)

    ml_risk = result["risk"]

    fusion = fuse_risk(
        zta_decision,
        ml_risk
    )

    print(f"ZTA Decision       : {zta_decision}")
    print(f"ML Prediction      : {result['prediction']}")
    print(f"ML Probability     : {result['anomaly_probability']:.2f}")
    print(f"ML Risk            : {ml_risk}")
    print(f"Final Decision     : {fusion.final_decision}")
    print(f"Reason             : {fusion.reason}")


# ---------------------------------------------------------
# Benign-looking activity
# ---------------------------------------------------------

benign_features = {
    "event_count": 2,
    "unique_processes": 1,
    "process_changes": 0,
    "unique_paths": 1,
    "mean_path_depth": 3.0,
    "max_path_depth": 3,
    "dominant_path_ratio": 1.0,
    "repetition_ratio": 0.5,
    "sequence_entropy": 0.0,
    "unique_pids": 1,
    "unique_uids": 1,
    "uid_changes": 0,
    "duration": 0.01,
    "event_rate": 200.0,
    "mean_delta": 0.01,
    "max_delta": 0.02,
    "std_delta": 0.0,
    "burst_count": 1,
    "bin_path_ratio": 1.0,
    "usr_path_ratio": 0.0,
    "tmp_path_ratio": 0.0,
    "sbin_path_ratio": 0.0,
    "path_diversity": 0.1,
}


# ---------------------------------------------------------
# More complex behavioral activity
# ---------------------------------------------------------

suspicious_features = {
    "event_count": 12,
    "unique_processes": 4,
    "process_changes": 8,
    "unique_paths": 8,
    "mean_path_depth": 4.5,
    "max_path_depth": 7,
    "dominant_path_ratio": 0.35,
    "repetition_ratio": 0.75,
    "sequence_entropy": 2.5,
    "unique_pids": 4,
    "unique_uids": 1,
    "uid_changes": 0,
    "duration": 0.15,
    "event_rate": 80.0,
    "mean_delta": 0.012,
    "max_delta": 0.04,
    "std_delta": 0.01,
    "burst_count": 5,
    "bin_path_ratio": 0.50,
    "usr_path_ratio": 0.30,
    "tmp_path_ratio": 0.20,
    "sbin_path_ratio": 0.0,
    "path_diversity": 0.75,
}


print()
print("============================================================")
print("KernelGuard ML + Risk Fusion Integration Test")
print("============================================================")

# Authorized benign activity
test_case(
    "TEST 1: Authorized benign activity",
    "ALLOW",
    benign_features
)

# Authorized but suspicious activity
test_case(
    "TEST 2: Authorized suspicious activity",
    "ALLOW",
    suspicious_features
)

# ZTA denial must always win
test_case(
    "TEST 3: ZTA DENY must override ML",
    "DENY",
    benign_features
)

print()
print("============================================================")
print("Integration test completed")
print("============================================================")
