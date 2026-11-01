#!/usr/bin/env python3

import os
import joblib
import pandas as pd


BASE = os.path.expanduser("~/kernelguard")

MODEL_PATH = os.path.join(
    BASE,
    "model/random_forest_behavior_model.joblib"
)

FEATURE_PATH = os.path.join(
    BASE,
    "model/behavior_features.joblib"
)


class BehaviorML:
    """
    KernelGuard behavioral ML inference engine.

    The model provides a behavioral risk assessment.
    It does NOT perform kernel enforcement.
    """

    def __init__(
        self,
        model_path=MODEL_PATH,
        feature_path=FEATURE_PATH
    ):

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found: {model_path}"
            )

        if not os.path.exists(feature_path):
            raise FileNotFoundError(
                f"Feature list not found: {feature_path}"
            )

        self.model = joblib.load(model_path)
        self.features = joblib.load(feature_path)

    def predict(self, feature_data):
        """
        Perform behavioral prediction.

        feature_data must contain the 23 behavioral
        features used during training.
        """

        values = []

        for feature in self.features:

            values.append(
                float(
                    feature_data.get(
                        feature,
                        0.0
                    )
                )
            )

        X = pd.DataFrame(
            [values],
            columns=self.features
        )

        prediction = int(
            self.model.predict(X)[0]
        )

        probability = 0.0

        if hasattr(
            self.model,
            "predict_proba"
        ):

            probabilities = (
                self.model.predict_proba(X)[0]
            )

            if len(probabilities) > 1:

                probability = float(
                    probabilities[1]
                )

        # ----------------------------------------------------
        # Behavioral risk classification
        # ----------------------------------------------------

        if probability >= 0.80:

            risk = "HIGH"

        elif probability >= 0.50:

            risk = "MEDIUM"

        else:

            risk = "LOW"

        return {

            "prediction":
                prediction,

            "anomaly_probability":
                round(
                    probability,
                    4
                ),

            "risk":
                risk
        }


def load_model():

    return BehaviorML()


# ============================================================
# SMOKE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("KernelGuard Behavioral ML")
    print("=" * 60)

    detector = BehaviorML()

    print(
        "[+] Model loaded successfully"
    )

    print(
        f"[+] Model: {MODEL_PATH}"
    )

    print(
        f"[+] Features: "
        f"{len(detector.features)}"
    )

    print("\n[+] Feature list:")

    for i, feature in enumerate(
        detector.features,
        start=1
    ):

        print(
            f"    {i:02d}. {feature}"
        )

    # --------------------------------------------------------
    # Benign-like smoke test
    # --------------------------------------------------------

    benign_test = {
        feature: 0.0
        for feature in detector.features
    }

    result = detector.predict(
        benign_test
    )

    print("\n[+] Smoke-test prediction:")
    print(result)

    print("\n[+] Behavioral ML module is ready.")
