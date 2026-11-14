# KernelGuard Behavioral ML

KernelGuard uses an out-of-band behavioral anomaly detector.

Algorithm:
Isolation Forest

Training:
Benign KernelGuard execution behaviour

Features:
- executable categories
- executable diversity
- risk level
- policy review frequency
- denied operations
- UID context
- behaviour transitions
- suspicious action transitions
- sensitive action frequency

The model does not replace deterministic Zero Trust enforcement.

BPF-LSM remains the final enforcement authority.

ML output:
NORMAL / ANOMALY

Architecture:

BPF-LSM
   |
KernelGuard Events
   |
Behaviour Features
   |
Isolation Forest
   |
Anomaly Score
   |
Review / Alert

The current implementation is intended as a research prototype
and controlled experimental evaluation, not a production security
classifier.


## Paths after repository cleanup

Training/evaluation scripts resolve the repository root from their own file location and read datasets from `research/dataset/ml_v2/`. Saved evaluation outputs go under `research/results/`. The final training script writes model artifacts to `research/models/artifacts/`; these are generated locally and are not committed by default. The inference wrapper accepts `KG_ML_ARTIFACT_DIR`, `KG_ML_MODEL_PATH` and `KG_ML_FEATURE_PATH` overrides.

Dataset collection scripts use the legacy monitor log at `~/kernelguard/logs/kernelguard_live.log` by default. Set `KG_LEGACY_LOG` to override it. They write into `research/dataset/ml_v2/` and refuse to overwrite existing CSV files unless `KG_OVERWRITE_DATASET=1` is explicitly set. They still parse the legacy text log format, not the canonical BPF ring-buffer JSON stream.
