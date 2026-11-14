#!/usr/bin/env python3

import os
from pathlib import Path

import joblib
import pandas as pd


HERE = Path(__file__).resolve().parent
ARTIFACT_DIR = Path(os.environ.get("KG_ML_ARTIFACT_DIR", HERE / "artifacts"))
MODEL_PATH = Path(os.environ.get("KG_ML_MODEL_PATH", ARTIFACT_DIR / "random_forest_behavior_model.joblib"))
FEATURE_PATH = Path(os.environ.get("KG_ML_FEATURE_PATH", ARTIFACT_DIR / "behavior_features.joblib"))


class BehaviorML:
    """
    Behavioural ML inference wrapper.
    This module provides risk assessment only; it does not enforce kernel policy.
    Model artifacts must be supplied separately in ARTIFACT_DIR or via env vars.
    """

    def __init__(self, model_path=MODEL_PATH, feature_path=FEATURE_PATH):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(feature_path):
            raise FileNotFoundError(f"Feature list not found: {feature_path}")
        self.model = joblib.load(model_path)
        self.features = joblib.load(feature_path)

    def predict(self, feature_data):
        values = [float(feature_data.get(feature, 0.0)) for feature in self.features]
        X = pd.DataFrame([values], columns=self.features)
        prediction = int(self.model.predict(X)[0])
        probability = 0.0
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X)[0]
            if len(probabilities) > 1:
                probability = float(probabilities[1])
        if probability >= 0.80:
            risk = "HIGH"
        elif probability >= 0.50:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        return {"prediction": prediction, "anomaly_probability": round(probability, 4), "risk": risk}


def load_model():
    return BehaviorML()


if __name__ == "__main__":
    detector = BehaviorML()
    print("[+] Behavioural model loaded")
    print(f"[+] Model: {MODEL_PATH}")
    print(f"[+] Features: {len(detector.features)}")
    benign_test = {feature: 0.0 for feature in detector.features}
    print("[+] Smoke-test prediction:", detector.predict(benign_test))
