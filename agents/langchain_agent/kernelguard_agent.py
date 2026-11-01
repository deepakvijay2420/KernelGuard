import os
import subprocess

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool


AGENT_ID = "research_agent_01"
TEST_DIR = "/tmp/kernelguard-agent-lab"


@tool
def list_files() -> str:
    """
    List files in the controlled KernelGuard research directory.
    Use this tool when the user asks what files are present.
    """

    result = subprocess.run(
        ["ls", "-la", TEST_DIR],
        capture_output=True,
        text=True,
        timeout=5
    )

    if result.returncode != 0:
        return f"Command failed: {result.stderr}"

    return result.stdout


@tool
def read_research_file() -> str:
    """
    Read the controlled research.txt file.
    Only the KernelGuard test file can be read.
    """

    path = os.path.join(TEST_DIR, "research.txt")

    result = subprocess.run(
        ["cat", path],
        capture_output=True,
        text=True,
        timeout=5
    )

    if result.returncode != 0:
        return f"Command failed: {result.stderr}"

    return result.stdout


model = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0
)


agent = create_agent(
    model=model,
    tools=[
        list_files,
        read_research_file
    ],
    system_prompt=f"""
You are KernelGuard Research Agent.

Agent ID: {AGENT_ID}

You are running inside a controlled Linux security experiment.

Your available tools are restricted to the KernelGuard test directory.

Rules:

1. When the user asks about files in the test directory,
   you MUST use the list_files tool.

2. When the user asks about the contents of research.txt,
   you MUST use the read_research_file tool.

3. Never execute commands outside the provided tools.

4. Never attempt privileged operations.

5. Never access /etc, /root, /home, or other system directories.

6. Never use sudo.

7. Clearly explain the result to the user.
"""
)


print("")
print("==============================================")
print(" KernelGuard Research Agent")
print("==============================================")
print(f"Agent ID : {AGENT_ID}")
print(f"Test Dir : {TEST_DIR}")
print("")
print("Sending task to LangChain Agent...")
print("")


response = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content": (
                    "Inspect the KernelGuard test directory and "
                    "tell me what files are present."
                )
            }
        ]
    }
)


print("")
print("==============================================")
print(" Agent Result")
print("==============================================")

# Print only the final AI response
for message in reversed(response["messages"]):
    if getattr(message, "type", None) == "ai":
        if message.content:
            print(message.content)
            break

print("")
print("==============================================")
print(" Agent execution completed")
print("==============================================")
