#!/bin/bash

# ==============================================================
# KernelGuard + LangChain + Gemini
# Final Agent Identity / Linux Execution Correlation Test
# ==============================================================

set -u
set -o pipefail

PROJECT="/home/deepak/kernelguard"
AGENT_DIR="$PROJECT/agents/langchain_agent"
LAB_DIR="/tmp/kernelguard-agent-lab"
LOG_DIR="$PROJECT/logs/agent_identity"

AGENT_ID="research_agent_01"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

AGENT_LOG="$LOG_DIR/agent_$TIMESTAMP.log"
EVENT_LOG="$LOG_DIR/kernelguard_$TIMESTAMP.log"
PROCESS_LOG="$LOG_DIR/process_$TIMESTAMP.log"
TOOL_LOG="$LOG_DIR/tool_pids_$TIMESTAMP.log"
SUMMARY_LOG="$LOG_DIR/summary_$TIMESTAMP.txt"

PID_FILE="/tmp/kernelguard_agent_pid"

mkdir -p "$LOG_DIR"

# ==============================================================
# Cleanup
# ==============================================================

JOURNAL_PID=""

cleanup()
{
    if [ -n "$JOURNAL_PID" ]; then
        sudo kill "$JOURNAL_PID" 2>/dev/null || true
        JOURNAL_PID=""
    fi
}

trap cleanup EXIT INT TERM


# ==============================================================
# Header
# ==============================================================

clear

echo
echo "=============================================================="
echo "        KERNELGUARD + LANGCHAIN AGENT"
echo "        FINAL INTEGRATION TEST"
echo "=============================================================="
echo
echo "Agent ID : $AGENT_ID"
echo "Project  : $PROJECT"
echo


# ==============================================================
# 1. Python environment
# ==============================================================

echo "=============================================================="
echo " 1. PYTHON ENVIRONMENT"
echo "=============================================================="

if [ ! -d "$AGENT_DIR/.venv" ]; then
    echo "[ERROR] Virtual environment not found:"
    echo "$AGENT_DIR/.venv"
    exit 1
fi

source "$AGENT_DIR/.venv/bin/activate"

echo "[OK] Python virtual environment activated"

PYTHON_VERSION=$(python --version 2>&1)
echo "[OK] $PYTHON_VERSION"

LANGCHAIN_VERSION=$(python -c \
'import langchain; print(langchain.__version__)' \
2>/dev/null || echo "unknown")

echo "[OK] LangChain version: $LANGCHAIN_VERSION"

echo


# ==============================================================
# 2. Gemini API key
# ==============================================================

echo "=============================================================="
echo " 2. GEMINI API"
echo "=============================================================="

if [ -z "${GOOGLE_API_KEY:-}" ]; then

    echo
    echo "Gemini API key is not currently exported."
    echo

    read -r -s -p "Enter Gemini API key: " GOOGLE_API_KEY
    echo

    export GOOGLE_API_KEY
fi

if [ -z "${GOOGLE_API_KEY:-}" ]; then
    echo "[ERROR] GOOGLE_API_KEY is empty."
    exit 1
fi

echo "[OK] Gemini API key available"

echo
echo "Testing Gemini API..."

API_TEST=$(python - <<'PY'
from langchain_google_genai import ChatGoogleGenerativeAI

try:
    model = ChatGoogleGenerativeAI(
        model="gemini-3.8-flash",
        temperature=0
    )

    response = model.invoke(
        "Reply with exactly: KernelGuard API OK"
    )

    print(response.content)

except Exception as e:
    print("ERROR:", e)
PY
)

if echo "$API_TEST" | grep -q "KernelGuard API OK"; then
    echo "[OK] Gemini API test successful"
else
    echo
    echo "[ERROR] Gemini API test failed."
    echo
    echo "$API_TEST"
    exit 1
fi

echo


# ==============================================================
# 3. Sudo
# ==============================================================

echo "=============================================================="
echo " 3. SYSTEM ACCESS"
echo "=============================================================="

sudo -v

if [ $? -ne 0 ]; then
    echo "[ERROR] sudo authentication failed."
    exit 1
fi

echo "[OK] sudo access available"

echo


# ==============================================================
# 4. KernelGuard services
# ==============================================================

echo "=============================================================="
echo " 4. KERNELGUARD SERVICES"
echo "=============================================================="

sudo systemctl start kernelguard-ebpf.service

sleep 2

sudo systemctl start kernelguard-reader.service

sleep 2

if systemctl is-active --quiet kernelguard-ebpf.service; then
    echo "[OK] kernelguard-ebpf.service running"
else
    echo "[ERROR] kernelguard-ebpf.service failed"
    sudo systemctl status kernelguard-ebpf.service --no-pager
    exit 1
fi

if systemctl is-active --quiet kernelguard-reader.service; then
    echo "[OK] kernelguard-reader.service running"
else
    echo "[ERROR] kernelguard-reader.service failed"
    sudo systemctl status kernelguard-reader.service --no-pager
    exit 1
fi

echo


# ==============================================================
# 5. Check BPF pins
# ==============================================================

echo "=============================================================="
echo " 5. BPF STATUS"
echo "=============================================================="

if [ -e /sys/fs/bpf/kernelguard_test ]; then
    echo "[OK] BPF-LSM program pin found"
else
    echo "[WARNING] kernelguard_test pin not found"
fi

if [ -e /sys/fs/bpf/kernelguard_events ]; then
    echo "[OK] Ring buffer pin found"
else
    echo "[WARNING] kernelguard_events pin not found"
fi

echo


# ==============================================================
# 6. Prepare controlled test directory
# ==============================================================

echo "=============================================================="
echo " 6. TEST ENVIRONMENT"
echo "=============================================================="

sudo mkdir -p "$LAB_DIR"
sudo chown "$USER":"$USER" "$LAB_DIR"

cat > "$LAB_DIR/research.txt" <<'EOF'
KernelGuard Agent Identity Experiment

Agent ID:
research_agent_01

Purpose:
Test whether Linux process execution generated by
an Agentic AI can be correlated with the Agent process.

Allowed operations:
- List this directory
- Read this file
EOF

echo "[OK] Test directory:"
echo "$LAB_DIR"

echo


# ==============================================================
# 7. Create LangChain agent
# ==============================================================

echo "=============================================================="
echo " 7. CREATING LANGCHAIN AGENT"
echo "=============================================================="

cat > "$AGENT_DIR/kernelguard_final_agent.py" <<'PYTHON'

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

TOOL_LOG = "/home/deepak/kernelguard/logs/agent_identity/tool_pids_current.log"


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

PYTHON

echo "[OK] LangChain agent created"

echo


# ==============================================================
# 8. Clear previous experiment files
# ==============================================================

rm -f "$PID_FILE"
rm -f "$TOOL_LOG"
rm -f /tmp/kernelguard_agent_tool_pids


# ==============================================================
# 9. Start LIVE KernelGuard journal capture
# ==============================================================

echo "=============================================================="
echo " 8. STARTING LIVE KERNELGUARD EVENT CAPTURE"
echo "=============================================================="

echo "[INFO] KernelGuard events will be captured while"
echo "       the Agent is running."

echo

sudo journalctl \
    -u kernelguard-reader.service \
    -f \
    -n 0 \
    --no-pager \
    -o cat \
    > "$EVENT_LOG" 2>&1 &

JOURNAL_PID=$!

sleep 2

if kill -0 "$JOURNAL_PID" 2>/dev/null; then
    echo "[OK] Live KernelGuard journal capture started"
else
    echo "[ERROR] Could not start journal capture"
    exit 1
fi

echo


# ==============================================================
# 10. Controlled KernelGuard probe
# ==============================================================

echo "=============================================================="
echo " 9. TESTING KERNELGUARD EVENT PIPELINE"
echo "=============================================================="

PROBE="/tmp/kernelguard_identity_probe"

cp /bin/echo "$PROBE"
chmod +x "$PROBE"

echo "[INFO] Executing controlled probe..."

"$PROBE" "KernelGuard identity probe"

sleep 2

if grep -q "$PROBE" "$EVENT_LOG"; then

    echo "[OK] KernelGuard event pipeline confirmed"

else

    echo
    echo "[WARNING] Probe event not found in journal yet."
    echo "[INFO] Continuing with Agent test."
    echo
fi

rm -f "$PROBE"

echo


# ==============================================================
# 11. Start Agent
# ==============================================================

echo "=============================================================="
echo " 10. STARTING LANGCHAIN AGENT"
echo "=============================================================="

START_TIME=$(date --iso-8601=seconds)

echo "[INFO] Experiment start:"
echo "$START_TIME"

echo

python "$AGENT_DIR/kernelguard_final_agent.py" \
    > "$AGENT_LOG" 2>&1 &

AGENT_LAUNCHER_PID=$!

echo "[OK] Agent launcher PID: $AGENT_LAUNCHER_PID"


# ==============================================================
# 12. Wait for Agent PID
# ==============================================================

AGENT_PID=""

for i in $(seq 1 40); do

    if [ -f "$PID_FILE" ]; then

        AGENT_PID=$(cat "$PID_FILE")

        if [ -n "$AGENT_PID" ]; then
            break
        fi

    fi

    sleep 0.5

done


if [ -z "$AGENT_PID" ]; then

    echo
    echo "[ERROR] Agent PID could not be obtained."
    echo

    cat "$AGENT_LOG"

    kill "$AGENT_LAUNCHER_PID" 2>/dev/null || true

    exit 1

fi


echo
echo "[OK] Agent PID: $AGENT_PID"


# ==============================================================
# 13. Capture Agent process identity WHILE RUNNING
# ==============================================================

echo
echo "=============================================================="
echo " 11. AGENT PROCESS IDENTITY"
echo "=============================================================="

{
    echo "Agent ID : $AGENT_ID"
    echo "Agent PID: $AGENT_PID"
    echo

    echo "Process:"
    ps -p "$AGENT_PID" \
        -o pid,ppid,uid,user,comm,args

    AGENT_PARENT_PID=$(ps -p "$AGENT_PID" -o ppid= | tr -d ' ')

    echo
    echo "Agent Parent PID: $AGENT_PARENT_PID"

    if [ -n "$AGENT_PARENT_PID" ]; then

        echo
        echo "Parent Process:"

        ps -p "$AGENT_PARENT_PID" \
            -o pid,ppid,uid,user,comm,args

    fi

    echo
    echo "Agent Cgroup:"

    cat "/proc/$AGENT_PID/cgroup" 2>/dev/null || true

    echo
    echo "Agent Process Tree:"

    pstree -aps "$AGENT_PID" 2>/dev/null || true

} | tee "$PROCESS_LOG"


# ==============================================================
# 14. Wait for Agent
# ==============================================================

echo
echo "=============================================================="
echo " 12. WAITING FOR AGENT"
echo "=============================================================="

wait "$AGENT_LAUNCHER_PID"

AGENT_EXIT=$?

sleep 3

echo
echo "[INFO] Agent exit code: $AGENT_EXIT"


# ==============================================================
# 15. Stop live journal capture
# ==============================================================

if [ -n "$JOURNAL_PID" ]; then

    sudo kill "$JOURNAL_PID" 2>/dev/null || true

    sleep 1

    JOURNAL_PID=""

fi


# ==============================================================
# 16. Display Agent output
# ==============================================================

echo
echo "=============================================================="
echo " 13. AGENT OUTPUT"
echo "=============================================================="

cat "$AGENT_LOG"


# ==============================================================
# 17. Display tool PIDs
# ==============================================================

echo
echo "=============================================================="
echo " 14. AGENT TOOL PROCESSES"
echo "=============================================================="

if [ -f "$TOOL_LOG" ]; then

    cat "$TOOL_LOG"

else

    echo "[WARNING] Tool PID log not found."

fi


# ==============================================================
# 18. Display KernelGuard events
# ==============================================================

echo
echo "=============================================================="
echo " 15. KERNELGUARD EVENTS"
echo "=============================================================="

if [ -s "$EVENT_LOG" ]; then

    cat "$EVENT_LOG"

else

    echo "[WARNING] KernelGuard event log is empty."

fi


# ==============================================================
# 19. Search for expected commands
# ==============================================================

echo
echo "=============================================================="
echo " 16. SEARCHING FOR AGENT EXECUTIONS"
echo "=============================================================="

echo

if grep -E \
    "/usr/bin/ls|/usr/bin/cat|/tmp/kernelguard" \
    "$EVENT_LOG" >/dev/null 2>&1; then

    echo "[OK] Expected executable paths found in KernelGuard events."

    echo

    grep -E \
        "/usr/bin/ls|/usr/bin/cat|/tmp/kernelguard" \
        "$EVENT_LOG"

else

    echo "[WARNING] Expected ls/cat executable paths were not"
    echo "          found in the captured KernelGuard journal."

fi


# ==============================================================
# 20. PID correlation
# ==============================================================

echo
echo "=============================================================="
echo " 17. PID CORRELATION"
echo "=============================================================="

CORRELATION_FOUND=0

if [ -f "$TOOL_LOG" ]; then

    while read -r LINE; do

        TOOL_NAME=$(echo "$LINE" | sed -n 's/.*TOOL=\([^ ]*\).*/\1/p')
        CHILD_PID=$(echo "$LINE" | sed -n 's/.*PID=\([^ ]*\).*/\1/p')
        COMMAND=$(echo "$LINE" | sed -n 's/.*COMMAND=\(.*\)$/\1/p')

        if [ -n "$CHILD_PID" ]; then

            echo
            echo "Tool      : $TOOL_NAME"
            echo "Child PID : $CHILD_PID"
            echo "Command   : $COMMAND"

            MATCH=$(grep -E \
                "PID[[:space:]]*[:=][[:space:]]*$CHILD_PID([[:space:]]|$)|PID[[:space:]]+$CHILD_PID([[:space:]]|$)" \
                "$EVENT_LOG" 2>/dev/null || true)

            if [ -n "$MATCH" ]; then

                echo "[OK] KernelGuard event correlated with PID $CHILD_PID"

                echo "$MATCH"

                CORRELATION_FOUND=1

            else

                echo "[INFO] PID $CHILD_PID was not directly visible"
                echo "       in the captured KernelGuard text."

            fi

        fi

    done < "$TOOL_LOG"

fi


# ==============================================================
# 21. Additional executable correlation
# ==============================================================

echo
echo "=============================================================="
echo " 18. EXECUTABLE CORRELATION"
echo "=============================================================="

LS_FOUND=0
CAT_FOUND=0

if grep -q "/usr/bin/ls" "$EVENT_LOG" 2>/dev/null; then
    LS_FOUND=1
    echo "[OK] /usr/bin/ls detected by KernelGuard"
else
    echo "[INFO] /usr/bin/ls not found in journal"
fi

if grep -q "/usr/bin/cat" "$EVENT_LOG" 2>/dev/null; then
    CAT_FOUND=1
    echo "[OK] /usr/bin/cat detected by KernelGuard"
else
    echo "[INFO] /usr/bin/cat not found in journal"
fi


# ==============================================================
# 22. Final summary
# ==============================================================

echo
echo "=============================================================="
echo " 19. FINAL RESULT"
echo "=============================================================="

if [ "$LS_FOUND" -eq 1 ] && [ "$CAT_FOUND" -eq 1 ]; then

    RESULT="SUCCESS"

    echo
    echo "[SUCCESS]"
    echo
    echo "LangChain Agent successfully generated Linux"
    echo "executions that were observed by KernelGuard."
    echo
    echo "Gemini"
    echo "  ↓"
    echo "LangChain Agent"
    echo "  ↓"
    echo "Agent PID: $AGENT_PID"
    echo "  ↓"
    echo "Agent Tools"
    echo "  ↓"
    echo "/usr/bin/ls + /usr/bin/cat"
    echo "  ↓"
    echo "Linux Kernel"
    echo "  ↓"
    echo "BPF-LSM"
    echo "  ↓"
    echo "KernelGuard Reader"

else

    RESULT="PARTIAL"

    echo
    echo "[PARTIAL RESULT]"
    echo
    echo "The LangChain Agent completed, but the expected"
    echo "KernelGuard ls/cat events were not visible in"
    echo "the captured journal."

fi


# ==============================================================
# 23. Save report
# ==============================================================

cat > "$SUMMARY_LOG" <<EOF
==============================================================
KernelGuard Agent Identity Experiment
==============================================================

Date:
$(date)

Result:
$RESULT

Agent ID:
$AGENT_ID

Agent PID:
$AGENT_PID

Agent Parent PID:
${AGENT_PARENT_PID:-unknown}

Test Directory:
$LAB_DIR

Gemini:
gemini-3.8-flash

Expected Agent Tools:

1. list_files()
   -> /usr/bin/ls

2. read_research_file()
   -> /usr/bin/cat

--------------------------------------------------------------
FILES
--------------------------------------------------------------

Agent Log:
$AGENT_LOG

KernelGuard Event Log:
$EVENT_LOG

Process Log:
$PROCESS_LOG

Tool PID Log:
$TOOL_LOG

--------------------------------------------------------------
OBSERVATION
--------------------------------------------------------------

LS detected:
$LS_FOUND

CAT detected:
$CAT_FOUND

PID correlation:
$CORRELATION_FOUND

--------------------------------------------------------------
ARCHITECTURE
--------------------------------------------------------------

Gemini
    |
    v
LangChain Agent
    |
    v
Agent PID
    |
    v
Agent Tool
    |
    v
Child Linux Process
    |
    v
BPF-LSM
    |
    v
Ring Buffer
    |
    v
KernelGuard Reader
    |
    v
Zero Trust Policy

==============================================================
EOF


# ==============================================================
# 24. Final paths
# ==============================================================

echo
echo "=============================================================="
echo " 20. REPORTS"
echo "=============================================================="

echo
echo "Agent log:"
echo "$AGENT_LOG"

echo
echo "KernelGuard event log:"
echo "$EVENT_LOG"

echo
echo "Process log:"
echo "$PROCESS_LOG"

echo
echo "Tool PID log:"
echo "$TOOL_LOG"

echo
echo "Final summary:"
echo "$SUMMARY_LOG"

echo
echo "=============================================================="
echo " TEST FINISHED"
echo "=============================================================="
echo

