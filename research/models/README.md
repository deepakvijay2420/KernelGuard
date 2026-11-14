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
