import sys

sys.path.append("../daemon")

from policy_engine import PolicyEngine
from tools import ToolManager


policy = PolicyEngine("../policies/policy.yaml")

tools = ToolManager()


class ResearchAgent:

    def decide(self, prompt):

        prompt = prompt.lower()

        if "summarize" in prompt:
            return "summary"

        elif "bash" in prompt:
            return "shell"

        else:
            return "unknown"

    def execute(self, prompt):

        tool = self.decide(prompt)

        print("\nSelected Tool:", tool)

        if tool == "summary":

            document = tools.read_document()

            tools.summarize(document)

        elif tool == "shell":

            print("\nChecking Zero Trust Policy...")

            if policy.check_execution(
                    "research_agent",
                    "/bin/bash"):

                tools.shell()

            else:

                print("\n❌ KernelGuard Blocked Shell")

        else:

            print("Unknown Task")


agent = ResearchAgent()

prompt = input("Enter Prompt: ")

agent.execute(prompt)
