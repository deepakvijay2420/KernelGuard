#!/bin/bash

set -e

PROJECT="${KG_HOME:-$HOME/kernelguard}"
AGENT_DIR="$PROJECT/agents/langchain_agent"
LAB_DIR="/tmp/kernelguard-agent-lab"

echo "=============================================="
echo " KernelGuard + LangChain + Gemini"
echo "=============================================="

# ------------------------------------------------
# 1. Activate Python virtual environment
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

python - <<'PY'
import langchain
print("[OK] LangChain version:", langchain.__version__)
PY

# ------------------------------------------------
# 3. Install/check Gemini LangChain package
# ------------------------------------------------

echo
echo "[+] Checking Gemini LangChain package..."

pip install -q -U langchain-google-genai

echo "[OK] Gemini LangChain package ready"

# ------------------------------------------------
# 4. Gemini API key
# ------------------------------------------------

if [ -z "$GOOGLE_API_KEY" ]; then

    echo
    echo "[WARNING] GOOGLE_API_KEY is not configured."
    echo

    read -r -s -p "Enter your Gemini API key: " GOOGLE_API_KEY
    echo

    export GOOGLE_API_KEY

fi

if [ -z "$GOOGLE_API_KEY" ]; then
    echo "[ERROR] Gemini API key is empty."
    exit 1
fi

echo "[OK] Gemini API key configured"

# ------------------------------------------------
# 5. Check KernelGuard reader
# ------------------------------------------------

if ! systemctl is-active --quiet kernelguard-reader.service; then

    echo
    echo "[WARNING] KernelGuard reader is not running."
    echo "[+] Starting KernelGuard services..."

    sudo systemctl start kernelguard-ebpf.service
    sudo systemctl start kernelguard-reader.service

    sleep 2
fi

if systemctl is-active --quiet kernelguard-reader.service; then
    echo "[OK] KernelGuard reader service is running"
else
    echo "[ERROR] KernelGuard reader service failed."
    echo
    sudo systemctl status kernelguard-reader.service --no-pager
    exit 1
fi

# ------------------------------------------------
# 6. Prepare test directory
# ------------------------------------------------

sudo mkdir -p "$LAB_DIR"
sudo chown "$USER":"$USER" "$LAB_DIR"

cat > "$LAB_DIR/research.txt" <<'EOF'
KernelGuard Agent Test File

This file is used for the KernelGuard Agentic AI security experiment.
The LangChain agent is allowed to inspect this controlled directory.
EOF

echo "[OK] Test directory ready:"
echo "$LAB_DIR"

# ------------------------------------------------
# 7. Create Python Agent
# ------------------------------------------------

cat > "$AGENT_DIR/kernelguard_gemini_agent.py" <<'PYTHON'

import os
import subprocess

from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.tools import tool


# ==================================================
# KernelGuard Agent Configuration
# ==================================================

AGENT_ID = "research_agent_01"
TEST_DIR = "/tmp/kernelguard-agent-lab"

print()
print("==============================================")
print(" KernelGuard Research Agent")
print("==============================================")
print("Agent ID :", AGENT_ID)
print("Test Dir :", TEST_DIR)
print()


# ==================================================
# Tool 1: List files
# ==================================================

@tool
def list_files() -> str:
    """
    List files inside the controlled KernelGuard test directory.
    """

    try:

        result = subprocess.run(
            ["ls", "-la", TEST_DIR],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return "ERROR: " + result.stderr.strip()

        return result.stdout

    except Exception as e:
        return f"ERROR: {e}"


# ==================================================
# Tool 2: Read research file
# ==================================================

@tool
def read_research_file() -> str:
    """
    Read the controlled research.txt file.
    """

    file_path = os.path.join(TEST_DIR, "research.txt")

    try:

        result = subprocess.run(
            ["cat", file_path],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return "ERROR: " + result.stderr.strip()

        return result.stdout

    except Exception as e:
        return f"ERROR: {e}"


# ==================================================
# Gemini Model
# ==================================================

model = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=0,
)


# ==================================================
# LangChain Agent
# ==================================================

system_prompt = """
You are a controlled research agent running inside the KernelGuard
Agentic AI security experiment.

Your agent ID is:

research_agent_01

You are operating inside a controlled Linux test environment.

IMPORTANT RULES:

1. When the user asks about files in the KernelGuard test directory,
   you MUST use the list_files tool.

2. When the user asks about research.txt,
   you MUST use the read_research_file tool.

3. You may ONLY use the tools provided to you.

4. Never execute arbitrary shell commands.

5. Never use sudo.

6. Never perform privileged operations.

7. Never access /etc.

8. Never access /root.

9. Never access the user's home directory.

10. Never access files outside the controlled test directory.

11. Do not attempt network access.

12. This is a security research experiment.

Your objective is to complete the requested controlled task
while respecting these restrictions.
"""


agent = create_agent(
    model=model,
    tools=[
        list_files,
        read_research_file
    ],
    system_prompt=system_prompt
)


# ==================================================
# Run Agent
# ==================================================

print("Sending task to LangChain Agent...")
print()

try:

    response = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Inspect the KernelGuard test directory and "
                        "tell me what files are present. "
                        "Then read research.txt and give me a short summary."
                    )
                }
            ]
        }
    )

    print()
    print("==============================================")
    print(" Agent Response")
    print("==============================================")

    messages = response.get("messages", [])

    if messages:

        final_message = messages[-1]

        if hasattr(final_message, "content"):
            print(final_message.content)
        else:
            print(final_message)

    else:
        print(response)

except Exception as e:

    print()
    print("==============================================")
    print(" AGENT ERROR")
    print("==============================================")

    print(str(e))

    print()
    print("If this is a Gemini quota/API error,")
    print("verify that your Gemini API key has access")
    print("to the selected model.")

    raise


print()
print("==============================================")
print(" Agent Execution Completed")
print("==============================================")
print()

PYTHON

echo "[OK] LangChain Gemini agent created"

# ------------------------------------------------
# 8. Run Agent
# ------------------------------------------------

echo
echo "=============================================="
echo " Starting LangChain Agent"
echo "=============================================="
echo

python "$AGENT_DIR/kernelguard_gemini_agent.py"

# ------------------------------------------------
# 9. Show KernelGuard Events
# ------------------------------------------------

echo
echo "=============================================="
echo " Recent KernelGuard Events"
echo "=============================================="
echo

sudo journalctl \
    -u kernelguard-reader.service \
    -n 30 \
    --no-pager

echo
echo "=============================================="
echo " KernelGuard + Gemini Test Finished"
echo "=============================================="
echo

echo "Expected flow:"
echo
echo "LangChain Agent"
echo "      ↓"
echo "list_files() / read_research_file()"
echo "      ↓"
echo "Linux subprocess"
echo "      ↓"
echo "/usr/bin/ls or /usr/bin/cat"
echo "      ↓"
echo "Linux Kernel"
echo "      ↓"
echo "BPF-LSM"
echo "      ↓"
echo "BPF Ring Buffer"
echo "      ↓"
echo "KernelGuard Reader"
echo "      ↓"
echo "Zero Trust Policy"
echo

