#!/usr/bin/env python3

import sys
import os
import yaml

# ============================================================
# KernelGuard Dynamic Policy Engine
# ============================================================

POLICY_PATH = "/home/deepak/kernelguard/policies/policy.yaml"


# ------------------------------------------------------------
# Load policy.yaml
# ------------------------------------------------------------

def load_policy():
    try:
        if not os.path.exists(POLICY_PATH):
            print(f"RISK=REVIEW")
            print(f"REASON=Policy file not found")
            print(f"ACTION=REVIEW")
            return None

        with open(POLICY_PATH, "r") as file:
            policy = yaml.safe_load(file)

        if not policy:
            print("RISK=REVIEW")
            print("REASON=Policy file is empty")
            print("ACTION=REVIEW")
            return None

        return policy

    except Exception:
        print("RISK=REVIEW")
        print("REASON=Policy loading failed")
        print("ACTION=REVIEW")
        return None


# ------------------------------------------------------------
# Check execution path against policy
# ------------------------------------------------------------

def evaluate_path(path, policy):

    try:
        security_monitor = policy.get("security_monitor", {})

        execution_policy = security_monitor.get(
            "execution_policy", {}
        )

        # ----------------------------------------------------
        # LOW RISK
        # ----------------------------------------------------

        low_risk = execution_policy.get(
            "low_risk", []
        )

        for item in low_risk:

            if path == item:

                return (
                    "LOW",
                    "Known standard system command",
                    "ALLOW"
                )

        # ----------------------------------------------------
        # MEDIUM RISK
        # ----------------------------------------------------

        medium_risk = execution_policy.get(
            "medium_risk", []
        )

        for item in medium_risk:

            if path == item:

                return (
                    "MEDIUM",
                    "Sensitive command detected",
                    "WARNING"
                )

        # ----------------------------------------------------
        # HIGH RISK
        # ----------------------------------------------------

        high_risk_paths = execution_policy.get(
            "high_risk_paths", []
        )

        for high_path in high_risk_paths:

            if path.startswith(high_path):

                return (
                    "HIGH",
                    "Execution from high-risk path",
                    "ALERT"
                )

        # ----------------------------------------------------
        # DEFAULT
        # ----------------------------------------------------

        default_action = execution_policy.get(
            "default_action",
            "REVIEW"
        )

        return (
            "REVIEW",
            "No matching policy rule",
            default_action
        )

    except Exception:

        return (
            "REVIEW",
            "Policy evaluation failed",
            "REVIEW"
        )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    # Check command-line argument
    if len(sys.argv) != 2:

        print("RISK=REVIEW")
        print("REASON=Invalid input")
        print("ACTION=REVIEW")

        return 1

    path = sys.argv[1]

    # Load policy
    policy = load_policy()

    if policy is None:
        return 1

    # Evaluate path
    risk, reason, action = evaluate_path(
        path,
        policy
    )

    # Output format used by kernelguard_reader.c
    print(f"RISK={risk}")
    print(f"REASON={reason}")
    print(f"ACTION={action}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
