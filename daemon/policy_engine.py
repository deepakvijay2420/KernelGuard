import yaml
import sys
import os


POLICY_PATH = os.path.expanduser("~/kernelguard/policies/policy.yaml")


def load_policy():
    """Load security policies from YAML file."""
    try:
        with open(POLICY_PATH, "r") as file:
            policy = yaml.safe_load(file)

        print("[+] Policy file loaded successfully")
        return policy

    except FileNotFoundError:
        print("[-] Policy file not found:", POLICY_PATH)
        sys.exit(1)

    except yaml.YAMLError as error:
        print("[-] Invalid YAML policy:", error)
        sys.exit(1)


def evaluate_execution(path, policy):
    """Evaluate executable path against security policies."""

    execution_policy = (
        policy
        .get("security_monitor", {})
        .get("execution_policy", {})
    )

    low_risk = execution_policy.get("low_risk", [])
    medium_risk = execution_policy.get("medium_risk", [])
    high_risk_paths = execution_policy.get("high_risk_paths", [])
    default_action = execution_policy.get("default_action", "REVIEW")

    # Check HIGH risk paths first
    for suspicious_path in high_risk_paths:
        if path.startswith(suspicious_path):
            return {
                "risk": "HIGH",
                "reason": f"Execution from suspicious path: {suspicious_path}"
            }

    # Check MEDIUM risk commands
    if path in medium_risk:
        return {
            "risk": "MEDIUM",
            "reason": "Sensitive command detected"
        }

    # Check LOW risk commands
    if path in low_risk:
        return {
            "risk": "LOW",
            "reason": "Known normal command"
        }

    # Default
    return {
        "risk": default_action,
        "reason": "No matching policy rule"
    }


def main():

    policy = load_policy()

    print("\n====================================")
    print(" KernelGuard Policy Engine Started")
    print("====================================")

    while True:

        try:
            path = input("\nEnter executable path (or 'exit'): ")

            if path.lower() == "exit":
                print("Policy Engine stopped.")
                break

            result = evaluate_execution(path, policy)

            print("\n------ POLICY DECISION ------")
            print("PATH   :", path)
            print("RISK   :", result["risk"])
            print("REASON :", result["reason"])
            print("-----------------------------")

        except KeyboardInterrupt:
            print("\nPolicy Engine stopped.")
            break


if __name__ == "__main__":
    main()
