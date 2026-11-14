from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool
import subprocess


@tool
def list_files() -> str:
    """List files in the KernelGuard agent test directory."""
    result = subprocess.run(
        ["ls", "-la", "/tmp/kernelguard-agent-lab"],
        capture_output=True,
        text=True
    )
    return result.stdout


@tool
def current_user() -> str:
    """Show the current Linux user."""
    result = subprocess.run(
        ["whoami"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()


model = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0
)

agent = create_agent(
    model=model,
    tools=[list_files, current_user],
    system_prompt=(
        "You are a controlled research agent for KernelGuard. "
        "Use the available tools only when necessary. "
        "Do not perform destructive or privileged actions."
    )
)


response = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content": "List the files in the KernelGuard test directory."
            }
        ]
    }
)

print("\n=== AGENT RESPONSE ===")

for message in response["messages"]:
    if hasattr(message, "content") and message.content:
        print(message.content)
