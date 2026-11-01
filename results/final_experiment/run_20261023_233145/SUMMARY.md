# KernelGuard Final Experimental Evaluation

**Run ID:** `20261023_233145`  
**Kernel:** `6.8.0-138-generic`  
**Generated:** `2026-10-23T23:31:47.378989+05:30`

## Objective

Evaluate the current KernelGuard prototype using controlled benign and attack-oriented Linux process execution scenarios.

## Test Dataset

- Total cases: **13**
- Benign cases: **7**
- Attack cases: **6**
- KernelGuard events collected: **40**

## Confusion Matrix

| Category | Correct Safe | Correct Deny | Errors |
|---|---:|---:|---:|
| Benign | TN = 7 | FP = 0 | 0 |
| Attack | FN = 2 | TP = 4 | 2 |

## Metrics

| Metric | Result |
|---|---:|
| Accuracy | 0.8462 |
| Precision | 1.0000 |
| Recall | 0.6667 |
| F1 Score | 0.8000 |
| False Positive Rate | 0.0000 |

## Decision Distribution

- ALLOW: **5**
- REVIEW: **4**
- DENY: **4**

## Latency

| Measurement | Result |
|---|---:|
| Minimum | 2783 µs |
| Average | 3724.46 µs |
| Median | 3674.00 µs |
| Maximum | 4549 µs |

> Latency represents controlled test and policy decision timing. It is not pure BPF-LSM hook latency.

## Observations

- 4 of 6 attack-oriented cases were classified as DENY.
- 2 attack-oriented cases were classified as REVIEW instead of DENY.
- 0 false positives were observed.
- Semantic misuse of an otherwise normal executable shows the limitation of executable-only rules.
- Contextual and behavioural analysis is therefore required for the next stage of KernelGuard.

## Current Implementation

```text
Linux Process
      |
      v
BPF-LSM
      |
      v
BPF Ring Buffer
      |
      v
KernelGuard Reader
      |
      v
Zero Trust Policy
      |
      v
ALLOW / REVIEW / DENY
```

## Limitations

- LSTM behavioural detection is not included in this measured experiment.
- LLM semantic adjudication is not included in the kernel enforcement path.
- DENY represents the current policy decision layer and should not be described as kernel-level EPERM enforcement.
- The dataset is small and controlled.
- Results should not be interpreted as production accuracy.

## Conclusion

The experiment demonstrates that KernelGuard can monitor Linux process execution using BPF-LSM and apply a Zero Trust policy to controlled execution scenarios. The REVIEW cases demonstrate the limitations of executable-only rules and motivate the addition of contextual and behavioural analysis.
