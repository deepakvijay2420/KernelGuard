import subprocess

class ResearchAgent:

    def __init__(self):

        self.name = "Research Agent"

    def prompt(self, instruction):

        print("\nInstruction Received:")

        print(instruction)

        print()

        if "bash" in instruction.lower():

            print("Executing Bash...\n")

            subprocess.run(["/bin/bash"])

        else:

            print("Reading document...")

            print("Generating summary...")

            with open("summary.txt", "w") as f:

                f.write("Summary created.")

            print("Task Completed.")


agent = ResearchAgent()

instruction = input("Enter Prompt: ")

agent.prompt(instruction)
