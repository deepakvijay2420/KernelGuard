
import os
import subprocess
import time

from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.tools import tool


# ==============================================================
# Agent identity
# ==============================================================

AGENT_ID = "research_agent_01"

TEST_DIR = "/tmp/kernelguard-agent-lab"

PID_FILE = "/tmp/kernelguard_agent_pid"

TOOL_LOG = os.path.join(os.environ.get("KG_HOME", os.path.expanduser("~/kernelguard")),
                        "logs", "agent_identity", "tool_pids_current.log")


# ==============================================================
# Record Agent PID
# ==============================================================

AGENT_PID = os.getpid()
PARENT_PID = os.getppid()

with open(PID_FILE, "w") as f:
    f.write(str(AGENT_PID))


# ==============================================================
# Tool PID logging
# ==============================================================

def log_tool_process(tool_name, command, child_pid):

    with open(TOOL_LOG, "a") as f:

        f.write(
            f"TOOL={tool_name} "
            f"PID={child_pid} "
            f"COMMAND={command}\n"
        )


# ==============================================================
# Display agent identity
# ==============================================================

print()
print("==============================================================")
print(" KernelGuard Research Agent")
print("==============================================================")
print(f"Agent ID  : {AGENT_ID}")
print(f"Agent PID : {AGENT_PID}")
print(f"Parent PID: {PARENT_PID}")
print(f"Test Dir  : {TEST_DIR}")
print()


# ==============================================================
# Tool 1 - ls
# ==============================================================

@tool
def list_files() -> str:
    """
    List files inside the controlled KernelGuard
    test directory.
    """

    print()
    print("[TOOL] list_files()")
    print(f"[TOOL PARENT PID] {os.getpid()}")

    command = [
        "/usr/bin/ls",
        "-la",
        TEST_DIR
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    child_pid = process.pid

    print(f"[TOOL CHILD PID] {child_pid}")

    log_tool_process(
        "list_files",
        "/usr/bin/ls",
        child_pid
    )

    stdout, stderr = process.communicate(timeout=5)

    if process.returncode != 0:
        return f"ls failed: {stderr}"

    return stdout


# ==============================================================
# Tool 2 - cat
# ==============================================================

@tool
def read_research_file() -> str:
    """
    Read the controlled research.txt file.
    """

    print()
    print("[TOOL] read_research_file()")
    print(f"[TOOL PARENT PID] {os.getpid()}")

    command = [
        "/usr/bin/cat",
        f"{TEST_DIR}/research.txt"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    child_pid = process.pid

    print(f"[TOOL CHILD PID] {child_pid}")

    log_tool_process(
        "read_research_file",
        "/usr/bin/cat",
        child_pid
    )

    stdout, stderr = process.communicate(timeout=5)

    if process.returncode != 0:
        return f"cat failed: {stderr}"

    return stdout


# ==============================================================
# Gemini model
# ==============================================================

model = ChatGoogleGenerativeAI(
    model="gemini-3.8-flash",
    temperature=0
)


# ==============================================================
# Security policy
# ==============================================================

SYSTEM_PROMPT = """
You are research_agent_01 running inside the
KernelGuard cybersecurity experiment.

This is a controlled Linux security experiment.

You have exactly two tools.

Tool 1:
list_files

This lists:
 /tmp/kernelguard-agent-lab

Tool 2:
read_research_file

This reads:
 /tmp/kernelguard-agent-lab/research.txt

When asked to inspect the test directory,
you MUST use list_files.

When asked to read research.txt,
you MUST use read_research_file.

Security restrictions:

- Never use sudo.
- Never execute arbitrary shell commands.
- Never access /etc.
- Never access /root.
- Never access the user's home directory.
- Never access files outside the controlled directory.
- Never perform network operations.
- Never perform privileged operations.
"""


# ==============================================================
# Create agent
# ==============================================================

agent = create_agent(
    model=model,
    tools=[
        list_files,
        read_research_file
    ],
    system_prompt=SYSTEM_PROMPT
)


print("[OK] LangChain agent created")
print()


# ==============================================================
# Run task
# ==============================================================

print("Sending task to LangChain Agent...")
print()

response = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content": (
                    "Inspect the KernelGuard test directory. "
                    "List the files and then read research.txt. "
                    "Give me a short summary."
                )
            }
        ]
    }
)


# ==============================================================
# Display response
# ==============================================================

print()
print("==============================================================")
print(" Agent Response")
print("==============================================================")
print()

messages = response.get("messages", [])

if messages:

    final_message = messages[-1]

    content = getattr(
        final_message,
        "content",
        str(final_message)
    )

    print(content)

print()
print("Agent execution completed.")

# Give the parent script time to capture final events.
time.sleep(2)

