import yaml
import os


POLICY_PATH = os.path.expanduser("~/kernelguard/policies/policy.yaml")


def load_policy():
    try:
        with open(POLICY_PATH, "r") as file:
            policy = yaml.safe_load(file)

        print("[+] Dynamic policy loaded successfully")
        return policy

    except FileNotFoundError:
        print("[!] Policy file not found")
        return {}

    except yaml.YAMLError as e:
        print(f"[!] Policy YAML error: {e}")
        return {}


def evaluate_policy(path, policy):

    # Navigate YAML structure:
    # security_monitor -> execution_policy
    security_monitor = policy.get("security_monitor", {})
    execution_policy = security_monitor.get("execution_policy", {})

    high_risk_paths = execution_policy.get("high_risk_paths", [])
    medium_risk_commands = execution_policy.get("medium_risk", [])
    low_risk_commands = execution_policy.get("low_risk", [])
    default_action = execution_policy.get("default_action", "REVIEW")

    # HIGH RISK
    for risky_path in high_risk_paths:
        if path.startswith(risky_path):
            return {
                "risk": "HIGH",
                "reason": "Execution from high-risk path",
                "action": "ALERT"
            }

    # MEDIUM RISK
    if path in medium_risk_commands:
        return {
            "risk": "MEDIUM",
            "reason": "Sensitive command detected",
            "action": "WARNING"
        }

    # LOW RISK
    if path in low_risk_commands:
        return {
            "risk": "LOW",
            "reason": "Known standard system command",
            "action": "ALLOW"
        }

    # DEFAULT / UNKNOWN
    return {
        "risk": default_action,
        "reason": "Executable not found in policy",
        "action": default_action
    }


if __name__ == "__main__":

    policy = load_policy()

    if not policy:
        print("[!] Cannot continue without a valid policy.")
        exit(1)

    print("\nKernelGuard Dynamic Policy Engine")
    print("----------------------------------")

    while True:

        try:
            path = input("\nEnter executable path (or 'exit'): ")

            if path.lower() == "exit":
                print("Policy Engine stopped.")
                break

            result = evaluate_policy(path, policy)

            print("\n----- POLICY DECISION -----")
            print("PATH   :", path)
            print("RISK   :", result["risk"])
            print("REASON :", result["reason"])
            print("ACTION :", result["action"])

        except KeyboardInterrupt:
            print("\nPolicy Engine stopped.")
            break
