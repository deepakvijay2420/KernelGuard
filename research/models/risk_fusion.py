#!/usr/bin/env python3

"""
KernelGuard Risk Fusion

Combines:
    1. Zero Trust authorization result
    2. Behavioral ML risk

Important:
    - ZTA DENY always wins.
    - ML is advisory.
    - ML does not directly enforce kernel-level blocking.
"""

from dataclasses import dataclass


@dataclass
class FusionResult:
    zta_decision: str
    ml_risk: str
    final_decision: str
    reason: str


def fuse_risk(zta_decision: str, ml_risk: str) -> FusionResult:

    zta_decision = zta_decision.upper()
    ml_risk = ml_risk.upper()

    # ---------------------------------------------------------
    # Rule 1: Zero Trust DENY always wins
    # ---------------------------------------------------------
    if zta_decision == "DENY":
        return FusionResult(
            zta_decision=zta_decision,
            ml_risk=ml_risk,
            final_decision="DENY",
            reason="Zero Trust policy denied the action"
        )

    # ---------------------------------------------------------
    # Rule 2: Authorized + LOW ML risk
    # ---------------------------------------------------------
    if zta_decision == "ALLOW" and ml_risk == "LOW":
        return FusionResult(
            zta_decision=zta_decision,
            ml_risk=ml_risk,
            final_decision="ALLOW",
            reason="Action is authorized and behavioral risk is low"
        )

    # ---------------------------------------------------------
    # Rule 3: Authorized + MEDIUM ML risk
    # ---------------------------------------------------------
    if zta_decision == "ALLOW" and ml_risk == "MEDIUM":
        return FusionResult(
            zta_decision=zta_decision,
            ml_risk=ml_risk,
            final_decision="REVIEW",
            reason="Action is authorized but behavioral risk is medium"
        )

    # ---------------------------------------------------------
    # Rule 4: Authorized + HIGH ML risk
    # ---------------------------------------------------------
    if zta_decision == "ALLOW" and ml_risk == "HIGH":
        return FusionResult(
            zta_decision=zta_decision,
            ml_risk=ml_risk,
            final_decision="REVIEW",
            reason="Action is authorized but behavioral risk is high"
        )

    # ---------------------------------------------------------
    # Rule 5: ZTA REVIEW
    # ---------------------------------------------------------
    if zta_decision == "REVIEW":
        if ml_risk == "HIGH":
            return FusionResult(
                zta_decision=zta_decision,
                ml_risk=ml_risk,
                final_decision="REVIEW",
                reason="Zero Trust requires review and behavioral risk is high"
            )

        return FusionResult(
            zta_decision=zta_decision,
            ml_risk=ml_risk,
            final_decision="REVIEW",
            reason="Zero Trust policy requires review"
        )

    # ---------------------------------------------------------
    # Unknown state: fail closed
    # ---------------------------------------------------------
    return FusionResult(
        zta_decision=zta_decision,
        ml_risk=ml_risk,
        final_decision="REVIEW",
        reason="Unknown security state; manual review required"
    )


def print_result(result: FusionResult):
    print()
    print("=" * 60)
    print("KernelGuard Risk Fusion")
    print("=" * 60)
    print(f"ZTA Decision   : {result.zta_decision}")
    print(f"ML Risk        : {result.ml_risk}")
    print(f"Final Decision : {result.final_decision}")
    print(f"Reason         : {result.reason}")
    print("=" * 60)


if __name__ == "__main__":

    print("KernelGuard Risk Fusion Test")
    print()

    test_cases = [
        ("ALLOW", "LOW"),
        ("ALLOW", "MEDIUM"),
        ("ALLOW", "HIGH"),
        ("DENY", "LOW"),
        ("DENY", "MEDIUM"),
        ("DENY", "HIGH"),
        ("REVIEW", "LOW"),
        ("REVIEW", "HIGH"),
    ]

    for zta, ml in test_cases:
        result = fuse_risk(zta, ml)

        print(
            f"ZTA={zta:6s} | "
            f"ML={ml:6s} | "
            f"FINAL={result.final_decision:6s}"
        )
