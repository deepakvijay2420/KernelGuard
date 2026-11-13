#!/usr/bin/env python3

import os
import re
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from behavior_features import extract_from_events
from behavior_ml import BehaviorML
from risk_fusion import fuse_risk


KG_HOME = Path(os.environ.get("KG_HOME", Path(__file__).resolve().parent.parent))
LOG_FILE = KG_HOME / "logs" / "kernelguard_live.log"


LINE_RE = re.compile(
    r"TIME=(.*?)\s*\|\s*"
    r"PID=(\d+)\s*\|\s*"
    r"UID=(\d+)\s*\|\s*"
    r"PROCESS=(.*?)\s*\|\s*"
    r"PATH=(.*?)\s*\|\s*"
    r"RISK=(.*?)\s*\|\s*"
    r"REASON=(.*?)\s*\|\s*"
    r"ACTION=(.*)"
)


def parse_log():

    events = []

    with LOG_FILE.open(
        "r",
        errors="replace"
    ) as f:

        for line in f:

            line = line.strip()

            match = LINE_RE.match(line)

            if not match:
                continue

            timestamp_text = match.group(1).strip()

            try:
                timestamp = datetime.strptime(
                    timestamp_text,
                    "%Y-%m-%d %H:%M:%S.%f"
                )
            except ValueError:
                continue

            events.append({
                "timestamp_start": timestamp,
                "timestamp_end": timestamp,

                "pid": int(match.group(2)),
                "uid": int(match.group(3)),

                "process": match.group(4).strip(),
                "path": match.group(5).strip(),

                "risk": match.group(6).strip(),
                "reason": match.group(7).strip(),
                "action": match.group(8).strip(),
            })

    return events


def main():

    print()
    print("=" * 70)
    print("KernelGuard Real-Time Behavioral ML Analysis")
    print("=" * 70)

    if not LOG_FILE.exists():

        print()
        print("[-] Log file not found:")
        print(LOG_FILE)

        return 1

    events = parse_log()

    print()
    print(f"[+] Timestamped events parsed : {len(events)}")

    if not events:

        print("[-] No timestamped events found.")

        return 1

    # --------------------------------------------------------
    # Extract exact 23 behavioral features
    # --------------------------------------------------------

    features = extract_from_events(events)

    print()
    print("[+] Behavioral features generated")
    print(f"[+] Feature count : {len(features)}")

    # --------------------------------------------------------
    # Display important temporal features
    # --------------------------------------------------------

    print()
    print("[+] Temporal behavior")
    print(
        f"    Duration      : "
        f"{features['duration']:.6f} sec"
    )

    print(
        f"    Event rate    : "
        f"{features['event_rate']:.2f} events/sec"
    )

    print(
        f"    Mean delta    : "
        f"{features['mean_delta']:.6f} sec"
    )

    print(
        f"    Max delta     : "
        f"{features['max_delta']:.6f} sec"
    )

    print(
        f"    Burst count   : "
        f"{features['burst_count']}"
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    model = BehaviorML()

    prediction = model.predict(features)

    print()
    print("[+] Behavioral ML")
    print(
        f"    Prediction          : "
        f"{prediction['prediction']}"
    )

    print(
        f"    Anomaly probability : "
        f"{prediction['anomaly_probability']:.2f}"
    )

    print(
        f"    ML risk             : "
        f"{prediction['risk']}"
    )

    # --------------------------------------------------------
    # Determine ZTA input
    #
    # Existing log contains policy-engine decisions.
    # For this offline integration test:
    #
    # WARNING/ALLOW -> ALLOW
    # REVIEW          -> REVIEW
    #
    # Explicit DENY is handled as DENY.
    # --------------------------------------------------------

    actions = [
        event["action"].upper()
        for event in events
    ]

    risks = [
        event["risk"].upper()
        for event in events
    ]

    if "DENY" in actions or "DENY" in risks:

        zta_decision = "DENY"

    elif "REVIEW" in actions or "REVIEW" in risks:

        zta_decision = "REVIEW"

    else:

        zta_decision = "ALLOW"

    # --------------------------------------------------------
    # Risk Fusion
    # --------------------------------------------------------

    fusion = fuse_risk(
        zta_decision,
        prediction["risk"]
    )

    print()
    print("[+] Risk Fusion")
    print(
        f"    ZTA decision  : "
        f"{zta_decision}"
    )

    print(
        f"    ML risk       : "
        f"{prediction['risk']}"
    )

    print(
        f"    Final decision: "
        f"{fusion.final_decision}"
    )

    print(
        f"    Reason        : "
        f"{fusion.reason}"
    )

    print()
    print("=" * 70)
    print("Real timestamp ML integration completed")
    print("=" * 70)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
