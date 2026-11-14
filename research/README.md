# Research assets

This directory preserves the project's experimental data, ML scripts and saved outputs.

- `dataset/`: controlled benign and attack-like CSVs, run metadata, scenario definitions and collection scripts.
- `models/`: training, feature engineering, cross-validation and attack-wise evaluation scripts from the research experiments.
- `results/`: saved metrics, reports, predictions and runtime experiment records.

## Important reproducibility notes

1. The documented dataset is synthetic/controlled and uses harmless command sequences; it is not a real-world malware benchmark.
2. Existing collectors parse a legacy text log schema, not the canonical BPF ring-buffer JSON schema.
3. The saved 1.000 ML metrics belong to one group-aware holdout experiment and must be presented alongside the lower five-fold results and dataset limitations.
4. The canonical runtime inference wrapper expects external joblib artifacts; the model artifacts are not included in the canonical implementation.
5. Historical scripts may contain absolute paths rooted at `~/kernelguard` and may need path updates after this directory relocation. Do not run them until their paths and dependencies have been checked.
6. Raw CSVs, scenario definitions, result files and metadata are retained. Do not regenerate over existing result directories without making a new run directory.
