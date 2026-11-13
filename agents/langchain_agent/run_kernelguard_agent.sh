#!/bin/bash

set -e

PROJECT="${KG_HOME:-$HOME/kernelguard}"
AGENT_DIR="$PROJECT/agents/langchain_agent"
LAB_DIR="/tmp/kernelguard-agent-lab"

echo "=============================================="
echo " KernelGuard + LangChain Agent"
echo "=============================================="

# ------------------------------------------------
# 1. Check virtual environment
# ------------------------------------------------

if [ ! -d "$AGENT_DIR/.venv" ]; then
    echo "[ERROR] Python virtual environment not found."
    echo "Expected: $AGENT_DIR/.venv"
    exit 1
fi

source "$AGENT_DIR/.venv/bin/activate"

echo "[OK] Python virtual environment activated"

# ------------------------------------------------
# 2. Check LangChain
# ------------------------------------------------

python -c "import langchain; print('[OK] LangChain version:', langchain.__version__)"

# ------------------------------------------------
# 3. Check OpenAI API key
# ------------------------------------------------

if [ -z "$OPENAI_API_KEY" ]; then
    echo ""
    echo "[WARNING] OPENAI_API_KEY is not configured."
    echo ""
    read -s -p "Enter your OpenAI API key: " OPENAI_API_KEY
    echo ""
    export OPENAI_API_KEY
fi

echo "[OK] OpenAI API key configured"

# ------------------------------------------------
# 4. Check KernelGuard reader
# ------------------------------------------------

if systemctl is-active --quiet kernelguard-reader.service; then
    echo "[OK] KernelGuard reader service is running"
else
    echo "[WARNING] KernelGuard reader service is not running"
    echo "[*] Starting KernelGuard services..."

    sudo systemctl start kernelguard-ebpf.service
    sudo systemctl start kernelguard-reader.service

    sleep 2

    if systemctl is-active --quiet kernelguard-reader.service; then
        echo "[OK] KernelGuard reader started"
    else
        echo "[ERROR] KernelGuard reader failed to start"
        sudo systemctl status kernelguard-reader.service --no-pager
        exit 1
    fi
fi

# ------------------------------------------------
# 5. Create controlled test directory
# ------------------------------------------------

mkdir -p "$LAB_DIR"

echo "KernelGuard Agent Test File" > "$LAB_DIR/research.txt"

echo "[OK] Test directory ready:"
echo "$LAB_DIR"

# ------------------------------------------------
# 6. Create LangChain Agent
# ------------------------------------------------

cat > "$AGENT_DIR/kernelguard_agent.py" <<'PYTHON'
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
PYTHON

# ------------------------------------------------
# 7. Run the agent
# ------------------------------------------------

echo ""
echo "=============================================="
echo " Starting LangChain Agent"
echo "=============================================="
echo ""

cd "$AGENT_DIR"

python kernelguard_agent.py

# ------------------------------------------------
# 8. Show recent KernelGuard events
# ------------------------------------------------

echo ""
echo "=============================================="
echo " Recent KernelGuard Events"
echo "=============================================="

sudo journalctl \
    -u kernelguard-reader.service \
    -n 20 \
    --no-pager

echo ""
echo "=============================================="
echo " Integration Test Complete"
echo "=============================================="

echo ""
echo "Expected flow:"
echo ""
echo "LangChain Agent"
echo "      ↓"
echo "list_files()"
echo "      ↓"
echo "/usr/bin/ls"
echo "      ↓"
echo "BPF-LSM"
echo "      ↓"
echo "Ring Buffer"
echo "      ↓"
echo "KernelGuard Reader"
echo ""

