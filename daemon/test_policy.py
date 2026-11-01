from policy_engine import PolicyEngine

engine = PolicyEngine("../policies/policy.yaml")

print("--------------------------------")

print("Research Agent -> Python")

print(engine.check(
    "research_agent",
    "execution",
    "/usr/bin/python3"
))

print("--------------------------------")

print("Research Agent -> Bash")

print(engine.check(
    "research_agent",
    "execution",
    "/bin/bash"
))

print("--------------------------------")

print("Code Agent -> Bash")

print(engine.check(
    "code_agent",
    "execution",
    "/bin/bash"
))
