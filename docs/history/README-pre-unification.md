# KernelGuard

## A Kernel-Level Runtime Security Framework for Agentic AI Systems Using eBPF and Zero Trust Architecture

KernelGuard is a Linux runtime security research prototype designed to monitor, identify, analyze, authorize, and control actions performed by Agentic AI systems.

The project addresses a security problem that becomes important when an AI system is no longer limited to generating text and is instead connected to operating-system tools, files, shell commands, applications, APIs, and other system resources.

An Agentic AI system can make decisions and invoke tools on behalf of a user. If the agent is manipulated through malicious instructions such as prompt injection, the resulting action may affect the underlying Linux system.

KernelGuard therefore places a security layer close to the Linux kernel and combines:

- eBPF / BPF-LSM for kernel-level monitoring and enforcement
- Process provenance for identifying agent-controlled processes
- Zero Trust Architecture (ZTA) for agent-specific authorization
- Behavioral Machine Learning for detecting suspicious execution patterns
- Risk Fusion for combining authorization and behavioral risk
- LangChain-based Agentic AI integration
- Prompt-injection attack simulation
- Deterministic kernel-level enforcement

The central security principle of KernelGuard is:

> Machine Learning and AI-based analysis can identify suspicious behavior, but deterministic kernel-level policy remains the final enforcement authority.

## Current implementation: ZTA v2

The active development version is documented separately under [`zta_v2/`](zta_v2/README.md). That guide describes the current cgroup-based agent identity, YAML policy, six BPF-LSM hooks, build steps, validation status, limitations, and safe testing workflow.

**Version note:** this root README also contains historical v1 architecture and research components. Do not assume that every capability described in the v1 sections is implemented in ZTA v2. For the current ZTA v2 implementation, use the [ZTA v2 documentation](zta_v2/README.md).

---

# 1. Problem Statement

Traditional application-level security controls may not be sufficient when an Agentic AI system is allowed to interact directly with the operating system.

An Agentic AI system can potentially:

- execute programs
- access files
- invoke shell commands
- access network resources
- interact with system utilities
- invoke privileged operations
- perform multiple actions sequentially

The main concern is not that the AI is automatically malicious.

The concern is that the agent can be influenced by:

- malicious prompts
- prompt injection
- malicious documents
- untrusted tool outputs
- compromised application context
- unexpected instructions

A malicious instruction may cause an otherwise legitimate agent to perform an unintended operating-system action.

For example:

```text
User
  |
  v
Agentic AI
  |
  v
Read document
  |
  v
Malicious instruction inside document
  |
  v
Agent decides to execute a command
  |
  v
Linux process
  |
  v
Privileged operation
```

KernelGuard attempts to control this final stage.

Instead of trusting the AI agent completely, KernelGuard observes the operating-system actions and applies security controls before dangerous execution is allowed to proceed.

---

# 2. Security Objective

The main objective of KernelGuard is to answer four questions for an operating-system action:

1. Who is performing the action?
2. Is the action authorized for that agent?
3. Does the behavior look abnormal?
4. Should the kernel allow or deny the action?

The system therefore separates:

```text
Identity
   +
Authorization
   +
Behavior
   =
Security Decision
```

The final decision is enforced at the Linux kernel boundary.

---

# 3. High-Level Architecture

The complete KernelGuard architecture is:

```text
                         USER
                           |
                           v
                    Agentic AI System
                           |
                           v
                    Agent Tools
                           |
                           v
                Linux Process / Execution
                           |
                           v
                 +--------------------+
                 |   BPF-LSM / eBPF  |
                 | Kernel Enforcement |
                 +--------------------+
                           |
                           v
                    BPF Ring Buffer
                           |
                           v
                 KernelGuard Reader
                           |
              +------------+-------------+
              |                          |
              v                          v
       Policy / ZTA                 Event Features
       Authorization                    |
              |                          v
              |                    Behavioral ML
              |                          |
              +------------+-------------+
                           |
                           v
                      Risk Fusion
                           |
                           v
                  Final Security Decision
                           |
                  +--------+--------+
                  |                 |
                ALLOW              DENY
                  |                 |
                  v                 v
              Continue          BPF-LSM
                               Enforcement
```

The architecture is intentionally divided into monitoring, analysis, authorization, and enforcement.

---

# 4. Why Kernel-Level Security?

An application-level security mechanism can be bypassed if the application itself is compromised or manipulated.

KernelGuard therefore observes actions at the Linux kernel boundary.

The Linux kernel is responsible for operations such as:

- process execution
- file access
- networking
- process creation
- privilege-related operations

By monitoring execution close to the kernel, KernelGuard can observe what the agent actually attempts to do rather than relying only on what the agent claims it intends to do.

This provides a stronger security boundary.

---

# 5. Why eBPF?

eBPF allows programs to execute safely inside the Linux kernel without modifying the kernel source code.

KernelGuard uses eBPF because it provides:

- kernel-level observability
- low-overhead event collection
- access to kernel execution points
- programmable security logic
- integration with Linux Security Module hooks
- communication between kernel and user space

The project specifically uses BPF-LSM for security enforcement.

---

# 6. Why BPF-LSM?

BPF-LSM allows eBPF programs to attach to Linux Security Module hooks.

KernelGuard currently uses:

```text
lsm/bprm_check_security
```

This hook is associated with program execution.

When a process attempts to execute a program, the KernelGuard BPF-LSM program can inspect the execution request.

Conceptually:

```text
Process wants to execute /usr/bin/sudo
                 |
                 v
        bprm_check_security
                 |
                 v
          KernelGuard BPF
                 |
          +------+------+
          |             |
       Allowed        Denied
          |             |
          v             v
       Execute       -EPERM
```

This makes BPF-LSM the final enforcement point.

---

# 7. eBPF Monitoring Layer

The primary monitoring program is:

```text
ebpf/exec_monitor.bpf.c
```

Its main responsibility is to monitor process execution.

The event structure contains:

```text
PID
UID
Process name
Executable path
```

The program collects the information and sends it to user space using a BPF Ring Buffer.

The current event structure is conceptually:

```text
struct exec_event
{
    pid
    uid
    comm
    filename
}
```

This provides the basic execution telemetry required by the rest of KernelGuard.

---

# 8. BPF Ring Buffer

The BPF Ring Buffer provides communication between the kernel-space eBPF program and the user-space KernelGuard reader.

The flow is:

```text
Linux Process
     |
     v
BPF-LSM Hook
     |
     v
eBPF Program
     |
     v
BPF Ring Buffer
     |
     v
KernelGuard Reader
```

The Ring Buffer avoids requiring the user-space process to continuously poll the kernel for every event.

KernelGuard uses the Ring Buffer to transfer execution events efficiently.

---

# 9. User-Space Reader

The main user-space monitoring component is:

```text
ebpf/kernelguard_reader.c
```

Its responsibilities include:

1. Connecting to the pinned Ring Buffer.
2. Receiving kernel execution events.
3. Extracting PID, UID, process and path.
4. Calling the policy engine.
5. Classifying the event.
6. Logging security events.
7. Passing behavioral information to the analysis layer.

The reader therefore acts as the bridge between:

```text
Kernel
  |
  v
Monitoring
  |
  v
Security Analysis
```

The reader does not itself replace kernel enforcement.

---

# 10. Policy Engine

The policy engine is implemented in:

```text
daemon/dynamic_policy_engine.py
```

The policy engine evaluates executable paths and assigns a security classification.

Example classifications include:

```text
LOW
MEDIUM
HIGH
REVIEW
```

Example actions include:

```text
ALLOW
WARNING
ALERT
REVIEW
```

Example policy behavior:

```text
/usr/bin/ls
    -> LOW
    -> ALLOW

/usr/bin/sudo
    -> MEDIUM
    -> WARNING

/bin/bash
    -> MEDIUM
    -> WARNING

/tmp/*
    -> HIGH
    -> ALERT

Unknown executable
    -> REVIEW
```

The purpose of this policy layer is to provide deterministic initial classification.

---

# 11. Why Zero Trust Architecture?

KernelGuard uses Zero Trust Architecture because an Agentic AI process should not automatically be trusted simply because it is part of a legitimate application.

The basic Zero Trust principle used in KernelGuard is:

> Never automatically trust an agent; verify its identity and authorize its action.

For an agent-controlled process, KernelGuard asks:

```text
Is this process associated with a registered agent?
                    |
                    v
Is this operation allowed for that agent?
                    |
                    v
ALLOW / DENY
```

This is different from simply checking whether the command itself is dangerous.

---

# 12. Agent Identity and Process Provenance

KernelGuard currently establishes agent identity at the process level.

The current prototype uses an agent root PID.

The Zero Trust enforcement component maintains:

```text
agent_roots
```

This map stores registered Agentic AI root processes.

When an execution occurs, the eBPF program checks:

```text
Current Process
      |
      v
Parent Process
      |
      v
Parent Process
      |
      v
...
```

The current implementation performs a bounded parent-ancestry lookup.

If a registered agent root is found, the process is considered associated with that agent.

Conceptually:

```text
Agent Root PID
      |
      +---- Python Agent
              |
              +---- Tool
              |
              +---- Shell
                      |
                      +---- /usr/bin/sudo
```

The execution of `sudo` can therefore be associated with the registered agent.

---

# 13. Important Agent Identity Limitation

KernelGuard does not claim that it can automatically identify every AI process on a Linux system.

The current prototype requires the agent root process to be registered with the Zero Trust controller.

Therefore:

```text
Registered Agent
      |
      +---- descendant process
              |
              +---- restricted action
                    |
                    v
                 ZTA policy
```

Human processes that are not associated with the registered agent are not automatically classified as Agentic AI processes.

This distinction is important because a command such as:

```text
sudo
```

does not itself prove that an AI agent executed it.

KernelGuard uses process provenance to establish the relationship.

---

# 14. Zero Trust Enforcement Implementation

The main Zero Trust eBPF program is:

```text
ebpf/zta/zta_enforcer.bpf.c
```

The user-space controller is:

```text
daemon/zta/zta_controller.c
```

The BPF program contains two important maps:

```text
agent_roots
blocked_rules
```

### agent_roots

Stores registered Agentic AI process identities.

Example:

```text
PID 23366 -> registered agent
```

### blocked_rules

Stores security rules that should be denied.

The current prototype includes rules for:

```text
/usr/bin/sudo
/bin/bash
/bin/sh
/usr/bin/passwd
```

The BPF program checks whether:

1. The current process belongs to a registered agent.
2. The executable matches a protected rule.
3. The rule is enabled.

If all conditions are satisfied:

```text
return -EPERM
```

The Linux kernel therefore prevents the execution.

---

# 15. Why Enforcement Is in the Kernel

Machine Learning can make mistakes.

An LLM can also make mistakes.

Therefore, KernelGuard does not allow ML or an LLM to directly control kernel enforcement.

The security hierarchy is:

```text
LLM / AI Analysis
       |
       v
Behavioral ML
       |
       v
Risk Fusion
       |
       v
Policy Decision
       |
       v
BPF-LSM
       |
       v
Kernel Enforcement
```

The kernel remains the final authority.

This reduces the risk of a false AI decision directly becoming a privileged operating-system action.

---

# 16. Agentic AI Integration

KernelGuard uses LangChain as a representative tool-using Agentic AI framework.

The purpose is not to claim that LangChain is the best Agentic AI framework.

It is used because the experiment requires an agent capable of:

- receiving instructions
- reasoning over information
- invoking tools
- reading files
- producing operating-system activity

The main agent implementation is located under:

```text
agents/langchain_agent/
```

The project includes several development versions, while:

```text
kernelguard_identity_agent_v2.py
```

represents the current identity-aware agent implementation.

---

# 17. Prompt Injection Demonstration

KernelGuard includes a controlled prompt-injection experiment.

Location:

```text
agents/prompt_injection_demo/
```

The demonstration contains:

```text
kernelguard_prompt_injection_demo.py
malicious_document.txt
```

The attack flow is:

```text
Agent
  |
  v
Read malicious document
  |
  v
Malicious instruction
  |
  v
Agent attempts privileged tool
  |
  v
/usr/bin/sudo
  |
  v
KernelGuard ZTA
  |
  v
BPF-LSM
  |
  v
EPERM
```

In the successful demonstration, the agent attempted the privileged operation but Linux returned:

```text
Operation not permitted
```

This demonstrates the intended security property:

> Prompt injection may influence the agent, but it should not automatically result in an unauthorized kernel-level operation.

---

# 18. Dataset

**Dataset methodology and reproducibility:** See the dedicated [ML v2 Dataset README](dataset/ml_v2/README.md) for the collection workflow, benign and attack-like scenario design, event/run CSV structure, labels, 23 behavioural features, regeneration steps, and limitations.

**Important scope note:** the current generator scripts parse the legacy KernelGuard live-log format. This dataset should not be described as captured from the ZTA v2 cgroup/BPF-LSM event pipeline. The attack-like generator runs controlled harmless command sequences; its `prompt_injection_*` labels are scenario names, not proof of a live LLM prompt-injection execution.


KernelGuard includes a behavioral dataset used for Machine Learning evaluation.

The dataset is located under:

```text
dataset/ml_v2/
```

The dataset contains:

```text
benign events
benign composite events
attack events
```

The dataset currently contains:

```text
Benign events : 1971
Attack events : 810
Total events  : 2781
```

The run-level dataset contains:

```text
800 benign runs
300 attack runs
1100 total runs
```

The dataset is designed to represent both normal system activity and suspicious/attack-oriented execution patterns.

---

# 19. Attack Categories

The attack dataset contains the following categories:

```text
prompt_injection_sudo
prompt_injection_bash
shell_execution_chain
password_utility
tmp_executable
unknown_executable
benign_to_sudo
benign_to_shell
repeated_sudo
repeated_shell
```

These categories represent different behavioral patterns rather than relying only on one attack signature.

Examples include:

### Prompt injection followed by sudo

```text
Agent
  |
  v
Malicious instruction
  |
  v
sudo attempt
```

### Shell execution

```text
Agent
  |
  v
Shell
  |
  v
Command chain
```

### Temporary executable

```text
/tmp/kernelguard-attack-test
```

### Unknown executable

```text
/tmp/kernelguard_unknown_exec
```

This allows the behavioral model to evaluate different types of suspicious execution.

---

# 20. Dataset Generation

Dataset generation scripts are located under:

```text
dataset/ml_v2/generators/
```

Important scripts include:

```text
collect_benign_dataset.py
collect_attack_dataset.py
collect_composite_benign.py
generate_benign.py
```

The general process is:

```text
Generate scenario
      |
      v
Execute commands
      |
      v
KernelGuard observes execution
      |
      v
Events recorded
      |
      v
Events labeled
      |
      v
Features extracted
      |
      v
ML dataset
```

The dataset therefore represents behavior observed by the KernelGuard monitoring layer.

---

# 21. Why Behavioral Features?

A security model should not depend only on exact command names.

For example:

```text
/usr/bin/sudo
```

can be legitimate in one context and suspicious in another.

Therefore KernelGuard extracts behavioral and temporal information from execution sequences.

The model currently uses 23 features.

---

# 22. The 23 Machine Learning Features

The feature extraction implementation is:

```text
model/behavior_features.py
```

The final feature set is:

```text
1.  event_count
2.  unique_processes
3.  process_changes
4.  unique_paths
5.  mean_path_depth
6.  max_path_depth
7.  dominant_path_ratio
8.  repetition_ratio
9.  sequence_entropy
10. unique_pids
11. unique_uids
12. uid_changes
13. duration
14. event_rate
15. mean_delta
16. max_delta
17. std_delta
18. burst_count
19. bin_path_ratio
20. usr_path_ratio
21. tmp_path_ratio
22. sbin_path_ratio
23. path_diversity
```

---

# 23. Feature Explanation

## event_count

Number of execution events observed during a run.

A suspicious automated workflow may generate a different number of events compared with a simple benign task.

## unique_processes

Number of different process names observed.

This helps identify execution diversity.

## process_changes

Number of transitions between different processes.

Useful for identifying process chains.

## unique_paths

Number of unique executable paths.

This measures executable diversity.

## mean_path_depth

Average depth of executable paths.

This can distinguish simple commands from more complex execution patterns.

## max_path_depth

Maximum path depth observed.

## dominant_path_ratio

Measures how strongly one executable dominates the execution sequence.

## repetition_ratio

Measures repeated execution behavior.

Repeated privileged operations may indicate automated or suspicious activity.

## sequence_entropy

Measures diversity/randomness of the execution sequence.

A more varied sequence can produce different entropy characteristics.

## unique_pids

Number of unique process IDs.

Useful for identifying process creation and execution behavior.

## unique_uids

Number of different user identities involved.

## uid_changes

Number of changes in user identity.

This is useful for detecting privilege or identity transitions.

## duration

Time between the beginning and end of the observed execution sequence.

## event_rate

Number of events generated per unit of time.

Automated activity can produce high event rates.

## mean_delta

Average time between consecutive events.

## max_delta

Maximum time gap between events.

## std_delta

Variation in the time gaps.

## burst_count

Number of closely grouped execution events.

This captures burst-like automated activity.

## bin_path_ratio

Ratio of executables under `/bin`.

## usr_path_ratio

Ratio of executables under `/usr`.

## tmp_path_ratio

Ratio of executables under `/tmp`.

Temporary executable activity can be security-sensitive.

## sbin_path_ratio

Ratio of executables under `/sbin`.

## path_diversity

Measures diversity of executable paths within a run.

---

# 24. Why These Features?

The important design decision is that the behavioral model should use execution characteristics rather than simply learning the policy labels.

Therefore the strict behavioral experiment removes direct policy-derived information such as:

```text
risk
reason
action
task_id
attack_id
label
```

It also avoids depending directly on exact executable identity.

The objective is to determine whether the model can learn behavioral differences from execution patterns.

---

# 25. Machine Learning Model

KernelGuard currently uses:

```text
Random Forest
```

The final model is trained using:

```text
RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)
```

The final trained model is intentionally kept outside GitHub as a binary artifact.

The reproducible training code is:

```text
model/train_final_behavior_model.py
```

The model can therefore be regenerated from the dataset.

---

# 26. Why Random Forest?

Random Forest was selected for the current behavioral analysis because:

- it works well with mixed numerical behavioral features
- it can model nonlinear relationships
- it does not require feature scaling
- it provides feature importance
- it is relatively simple to reproduce
- inference is fast enough for user-space behavioral analysis
- it performed well in the project evaluation compared with the other tested models

The project also evaluates:

```text
Logistic Regression
Random Forest
Gradient Boosting
```

The final prototype uses Random Forest as the reusable behavioral model.

---

# 27. ML Evaluation

KernelGuard performs scenario-level validation rather than relying only on random event-level splitting.

The 5-fold scenario-level evaluation produced approximately:

```text
Logistic Regression
Accuracy : 0.834
Precision: 0.879
Recall   : 0.650
F1       : 0.663

Random Forest
Accuracy : 0.829
Precision: 0.673
Recall   : 0.800
F1       : 0.682

Gradient Boosting
Accuracy : 0.799
Precision: 0.588
Recall   : 0.600
F1       : 0.562
```

The scenario-level evaluation is important because events from the same scenario should not simply appear in both training and testing sets.

---

# 28. Important ML Limitation

The Machine Learning model is not treated as the final security authority.

The dataset is relatively small and controlled.

Therefore the current ML results should be interpreted as a prototype behavioral evaluation rather than proof of production-grade detection.

The ML system is intended to:

```text
detect suspicious behavior
        |
        v
provide behavioral risk
        |
        v
support security decision
```

It is not intended to independently enforce privileged operations.

---

# 29. BehaviorML Module

The reusable ML interface is:

```text
model/behavior_ml.py
```

The main class is:

```text
BehaviorML
```

It loads the trained model and feature list.

The output is conceptually:

```text
prediction
anomaly_probability
risk
```

Example:

```text
prediction          : 0
anomaly_probability : 0.17
risk                : LOW
```

The ML module therefore provides a standardized behavioral risk result to the rest of KernelGuard.

---

# 30. Risk Fusion

Machine Learning and Zero Trust answer different questions.

ZTA asks:

> Is this action authorized for this agent?

ML asks:

> Does the observed behavior look suspicious?

KernelGuard combines these decisions through:

```text
model/risk_fusion.py
```

The current decision logic is:

```text
ZTA DENY
    |
    v
DENY
```

ZTA ALLOW + ML LOW:

```text
ALLOW
```

ZTA ALLOW + ML MEDIUM:

```text
REVIEW
```

ZTA ALLOW + ML HIGH:

```text
REVIEW
```

ZTA REVIEW:

```text
REVIEW
```

Unknown states:

```text
REVIEW
```

The system therefore follows a fail-safe approach.

---

# 31. Why ZTA Has Priority Over ML

Suppose ML says:

```text
LOW RISK
```

but Zero Trust says:

```text
DENY
```

KernelGuard does not allow the ML result to override the authorization policy.

The final result is:

```text
DENY
```

This is important because authorization and anomaly detection have different purposes.

A command may be behaviorally normal but still unauthorized for a particular agent.

Therefore:

```text
Behaviorally normal
        !=
Authorized
```

---

# 32. Complete Security Decision Flow

The complete decision process is:

```text
1. Process attempts execution
             |
             v
2. BPF-LSM observes execution
             |
             v
3. KernelGuard identifies process
             |
             v
4. Agent provenance is checked
             |
             v
5. ZTA policy is evaluated
             |
             v
6. Behavioral features are generated
             |
             v
7. ML calculates behavioral risk
             |
             v
8. Risk Fusion combines results
             |
             v
9. Final decision
             |
       +-----+------+
       |            |
     ALLOW         DENY
       |            |
       v            v
   Continue       -EPERM
```

---

# 33. Code / Repository Structure

The repository is organized according to the main KernelGuard components.

```text
KernelGuard/
|
+-- agents/
|   |
|   +-- langchain_agent/
|   |   |
|   |   +-- kernelguard_identity_agent_v2.py
|   |   +-- other agent implementations
|   |   +-- agent policies
|   |   +-- execution scripts
|   |
|   +-- prompt_injection_demo/
|       |
|       +-- kernelguard_prompt_injection_demo.py
|       +-- malicious_document.txt
|
+-- daemon/
|   |
|   +-- dynamic_policy_engine.py
|   +-- policy_engine.py
|   +-- test_policy.py
|   |
|   +-- zta/
|       +-- zta_controller.c
|
+-- ebpf/
|   |
|   +-- exec_monitor.bpf.c
|   +-- kernelguard_reader.c
|   +-- vmlinux.h
|   |
|   +-- zta/
|       +-- zta_enforcer.bpf.c
|       +-- zta_enforcer.skel.h
|       +-- vmlinux.h
|
+-- dataset/
|   |
|   +-- ml_v2/
|       +-- benign/
|       +-- attacks/
|       +-- generators/
|       +-- feature files
|
+-- model/
|   |
|   +-- behavior_features.py
|   +-- behavior_ml.py
|   +-- risk_fusion.py
|   +-- train_final_behavior_model.py
|   +-- run_5fold_scenario_cv.py
|   +-- run_attackwise_evaluation.py
|   +-- analyze_live_log.py
|   +-- experiment scripts
|
+-- policies/
|   |
|   +-- policy.yaml
|   +-- agent_policy.yaml
|
+-- results/
|   |
|   +-- final_experiment/
|   +-- ml/
|   +-- ml_v2/
|
+-- scripts/
|   +-- start_kernelguard.sh
|
+-- libbpf-bootstrap/
|
+-- README.md
+-- .gitignore
```

---

# 34. Code Responsibilities

## ebpf/

Contains kernel-space eBPF/BPF-LSM programs and kernel-to-user event monitoring components.

Main file:

```text
exec_monitor.bpf.c
```

Responsible for collecting execution events.

---

## ebpf/zta/

Contains the kernel-level Zero Trust enforcement implementation.

Main file:

```text
zta_enforcer.bpf.c
```

Responsible for:

- identifying registered agent ancestry
- checking protected executable rules
- enforcing denial
- returning `-EPERM`

---

## daemon/

Contains user-space security control logic.

The policy engine converts raw execution events into security classifications.

---

## daemon/zta/

Contains the user-space Zero Trust controller.

It:

- receives the agent PID
- validates the process
- registers the agent identity
- configures blocked rules
- loads the BPF enforcement program
- manages the enforcement lifecycle

---

## agents/

Contains Agentic AI experiments.

The directory includes:

- LangChain agents
- identity-aware agent
- prompt-injection demonstration
- malicious document
- tool implementations

---

## dataset/

Contains the data collection and evaluation pipeline.

It contains:

- benign data
- attack data
- composite benign workflows
- dataset generators
- extracted feature datasets

---

## model/

Contains the behavioral Machine Learning system.

Important modules:

```text
behavior_features.py
```

Extracts the 23 behavioral features.

```text
behavior_ml.py
```

Loads and executes the trained behavioral model.

```text
risk_fusion.py
```

Combines ZTA and ML results.

```text
train_final_behavior_model.py
```

Trains the final Random Forest model.

```text
run_5fold_scenario_cv.py
```

Performs scenario-level cross-validation.

```text
run_attackwise_evaluation.py
```

Evaluates performance against individual attack categories.

```text
analyze_live_log.py
```

Tests the behavioral model against timestamped KernelGuard events.

---

# 35. Policy Structure

KernelGuard uses policies to describe how execution events should be classified or restricted.

The policy files are located under:

```text
policies/
```

Important files include:

```text
policy.yaml
agent_policy.yaml
```

The general policy concept is:

```text
Executable
    |
    v
Risk Classification
    |
    v
Security Action
```

For example:

```text
/usr/bin/ls
    -> LOW
    -> ALLOW
```

while:

```text
/tmp/*
    -> HIGH
    -> ALERT
```

The ZTA enforcement prototype separately maintains protected execution rules for agent-controlled processes.

---

# 36. Why Policy and ML Are Separate

Policy and Machine Learning should not be mixed into one mechanism.

Policy provides:

```text
Deterministic authorization
```

ML provides:

```text
Behavioral analysis
```

Therefore:

```text
Policy
  |
  +--> "Is this authorized?"

ML
  |
  +--> "Does this look suspicious?"
```

Keeping these responsibilities separate makes the system easier to understand and safer to enforce.

---

# 37. Runtime Components

The KernelGuard runtime consists of:

```text
KernelGuard eBPF-LSM
        |
        v
Ring Buffer
        |
        v
KernelGuard Reader
        |
        v
Policy Engine
        |
        v
Behavior Analysis
        |
        v
Risk Fusion
        |
        v
Security Decision
```

The permanent service configuration allows the monitoring components to start automatically with the Linux system.

---

# 38. Security Model

KernelGuard follows these principles:

### Principle 1 — Least Privilege

An agent should only receive the permissions required for its intended task.

### Principle 2 — Continuous Verification

Agent identity and authorization are checked during execution.

### Principle 3 — Separation of Detection and Enforcement

ML detects suspicious behavior.

Kernel policy enforces the final decision.

### Principle 4 — Fail Safe

Unknown or ambiguous states should not automatically result in unrestricted execution.

### Principle 5 — Kernel-Level Enforcement

Critical denial decisions are enforced through BPF-LSM.

---

# 39. Example Normal Execution

Example:

```text
Agent
  |
  v
/usr/bin/ls
```

KernelGuard observes:

```text
Process execution
        |
        v
Agent provenance
        |
        v
ZTA: ALLOW
        |
        v
ML: LOW
        |
        v
Final: ALLOW
```

The operation proceeds normally.

---

# 40. Example Sensitive Execution

Example:

```text
Agent
  |
  v
/usr/bin/sudo
```

The event is classified as sensitive.

If the agent is registered and the ZTA policy blocks the executable:

```text
Agent provenance
        |
        v
ZTA: DENY
        |
        v
BPF-LSM
        |
        v
-EPERM
```

The command is prevented.

---

# 41. Example Prompt Injection

The prompt-injection experiment demonstrates:

```text
Malicious document
       |
       v
Agent reads document
       |
       v
Agent follows malicious instruction
       |
       v
Privileged tool invocation
       |
       v
/usr/bin/sudo
       |
       v
KernelGuard
       |
       v
ZTA DENY
       |
       v
Linux -EPERM
```

This demonstrates the intended separation between AI behavior and operating-system authorization.

---

# 42. Example High-Risk Temporary Executable

KernelGuard also tests executable files under `/tmp`.

Example:

```text
/tmp/kernelguard-attack-test
```

This represents a temporary executable scenario.

The policy layer can classify it as high risk:

```text
/tmp/*
    |
    v
HIGH
    |
    v
ALERT
```

This provides an additional security signal for behavioral analysis.

---

# 43. ML Feature Importance

The final Random Forest model identified several important features.

Examples include:

```text
usr_path_ratio
bin_path_ratio
mean_path_depth
unique_pids
burst_count
event_count
path_diversity
repetition_ratio
sequence_entropy
unique_paths
```

These features indicate that the model is using execution behavior and temporal characteristics rather than simply one command signature.

---

# 44. Real-Time Behavioral Analysis

KernelGuard also supports analysis of timestamped runtime events.

The reader records timestamps in the form:

```text
TIME=YYYY-MM-DD HH:MM:SS.mmm
```

This allows behavioral analysis to calculate:

- duration
- event rate
- time deltas
- burst count
- execution timing patterns

This is important because behavior is not only about what happened, but also about how the events occurred over time.

---

# 45. Why Timestamp Information Matters

Consider:

```text
10 commands over 10 minutes
```

versus:

```text
10 commands in 1 second
```

The event count is identical.

However, the behavioral characteristics are different.

Temporal features allow KernelGuard to capture this difference.

---

# 46. Current Research Contribution

The main contribution of KernelGuard is the combination of:

```text
Agent Provenance
       +
Zero Trust Authorization
       +
Kernel-Level Enforcement
       +
Temporal Behavioral Analysis
       +
Risk Fusion
```

The important design principle is that these components have separate responsibilities.

The project does not claim that Machine Learning alone can secure an Agentic AI system.

Instead:

```text
ML
 |
 +--> identifies suspicious behavior

ZTA
 |
 +--> determines authorization

BPF-LSM
 |
 +--> performs final enforcement
```

---

# 47. Current Capabilities

The current prototype supports:

- Linux execution monitoring
- eBPF-based monitoring
- BPF-LSM integration
- BPF Ring Buffer event transfer
- PID/UID/process/path collection
- policy-based event classification
- Agentic AI integration
- LangChain agent experiments
- process-based agent identity
- process ancestry checking
- Zero Trust execution rules
- deterministic BPF-LSM denial
- prompt-injection simulation
- behavioral dataset generation
- 23 behavioral features
- Random Forest behavioral model
- scenario-level ML validation
- attack-wise evaluation
- risk fusion
- timestamp-based runtime analysis
- permanent runtime service configuration

---

# 48. Current Limitations

KernelGuard is currently a research prototype.

Important limitations include:

1. Agent identity registration is currently controlled by the user-space controller.
2. Agent provenance currently uses bounded parent-process ancestry.
3. The current ZTA rules are a prototype policy set.
4. The current policy engine is not a complete enterprise authorization system.
5. The dataset is controlled and relatively small.
6. ML performance should not be interpreted as production-grade detection.
7. The current behavioral model operates on aggregated execution behavior.
8. Automatic universal AI-process discovery is not implemented.
9. The current prototype does not claim to detect every possible prompt-injection technique.
10. The LLM is not allowed to directly modify kernel enforcement policy.

These limitations define areas for future research.

---

# 49. Future Work

Future versions can investigate:

### Stronger Agent Provenance

Use:

- cgroups
- executable hashes
- process credentials
- parent-child relationships
- container identity
- runtime metadata

### More Kernel Hooks

Extend monitoring to:

- file operations
- network connections
- process creation
- privilege changes

### Better Behavioral Models

Evaluate:

- LSTM
- temporal transformers
- sequence models
- online anomaly detection

### Semantic Analysis

An LLM can be used as an out-of-band semantic adjudicator.

However, it should not directly control kernel enforcement.

### Better Policy Management

Future work can introduce:

- signed policies
- administrator-controlled policy storage
- policy versioning
- policy integrity verification
- dynamic but authenticated policy updates

---

# 50. Reproduction Environment

The prototype was developed using:

```text
Operating System:
Ubuntu 22.04 LTS

Kernel:
6.8 HWE

Compiler:
Clang / LLVM

eBPF:
libbpf
bpftool
BPF-LSM

Machine Learning:
Python
scikit-learn
NumPy
pandas
joblib

Agent Framework:
LangChain

LLM:
Gemini
```

The exact environment may require adjustment depending on the Linux kernel and installed eBPF tooling.

---

# 51. Basic Runtime Flow

A simplified runtime sequence is:

```text
1. Start KernelGuard eBPF-LSM
2. Attach execution monitoring
3. Start Ring Buffer
4. Start user-space reader
5. Register Agent root PID
6. Enable ZTA rules
7. Run Agentic AI task
8. Agent invokes a tool
9. Linux process attempts execution
10. BPF-LSM observes the operation
11. Agent provenance is checked
12. ZTA authorization is evaluated
13. Behavioral events are collected
14. ML analyzes execution behavior
15. Risk Fusion produces final decision
16. Kernel enforcement allows or denies the action
```

---

# 52. Design Philosophy

KernelGuard follows a simple security philosophy:

```text
Do not trust the agent blindly.

Observe what the agent actually does.

Verify who performed the action.

Determine whether the action is authorized.

Analyze the behavior.

Keep final enforcement deterministic.
```

This architecture is intended to reduce the impact of malicious or unintended Agentic AI behavior on Linux systems.

---

# 53. Research Scope

The current research focuses primarily on:

```text
Linux
+
Agentic AI
+
Prompt Injection
+
Process Provenance
+
eBPF / BPF-LSM
+
Zero Trust
+
Behavioral Machine Learning
```

The project is therefore a security research prototype rather than a general-purpose Linux security product.

---

# 54. Final Security Flow

The complete KernelGuard security model can be summarized as:

```text
                         AGENTIC AI
                              |
                              v
                         TOOL ACTION
                              |
                              v
                       LINUX EXECUTION
                              |
                              v
                    +-------------------+
                    |      BPF-LSM      |
                    | Kernel Observation|
                    +-------------------+
                              |
                              v
                       Ring Buffer
                              |
                              v
                    KernelGuard Reader
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
       Agent Provenance                   Behavioral Data
             |                                 |
             v                                 v
       ZTA Authorization                 ML Analysis
             |                                 |
             +----------------+----------------+
                              |
                              v
                         Risk Fusion
                              |
                              v
                    FINAL SECURITY DECISION
                              |
                    +---------+---------+
                    |                   |
                  ALLOW                DENY
                    |                   |
                    v                   v
                Continue             -EPERM
                                  BPF-LSM BLOCK
```

---

# 55. Project Status

Current implementation status:

```text
[✓] Linux eBPF environment
[✓] BPF-LSM execution monitoring
[✓] Ring Buffer event collection
[✓] User-space event reader
[✓] Policy engine
[✓] Agentic AI integration
[✓] Agent process identity
[✓] Process ancestry checking
[✓] ZTA enforcement prototype
[✓] Prompt-injection demonstration
[✓] Behavioral dataset
[✓] Behavioral feature extraction
[✓] Random Forest model
[✓] Scenario-level validation
[✓] Attack-wise evaluation
[✓] Risk Fusion
[✓] Timestamped runtime events
[✓] End-to-end privileged-operation blocking
[✓] GitHub repository
```

---

# 56. Summary

KernelGuard is designed around a layered security model for Agentic AI systems running on Linux.

The system does not rely on a single security mechanism.

Instead:

```text
eBPF/BPF-LSM
    -> observes and enforces

Agent Provenance
    -> identifies agent-controlled processes

ZTA
    -> determines whether the action is authorized

Behavioral ML
    -> identifies suspicious execution patterns

Risk Fusion
    -> combines authorization and behavioral risk

BPF-LSM
    -> performs final deterministic enforcement
```

The key principle is:

> AI-based analysis can provide intelligence, but security-critical enforcement should remain deterministic and close to the operating-system boundary.

---

# Author

**Deepak Vijay**

M.Tech — Cyber Security Systems and Networks

KernelGuard — Minor Project

---

# License

This project is intended primarily for academic and security research purposes.

---

# Detailed Architecture, Implementation and Research Methodology

## 1. Why KernelGuard Is Required

Traditional operating-system security mechanisms generally treat a process according to its operating-system identity, user identity, permissions, and executable.

Agentic AI introduces an additional security problem.

An Agentic AI system is not limited to generating text. When an AI agent is connected to tools, files, shell commands, APIs, or operating-system resources, it can cause real system-level actions.

For example, an AI agent may:

- execute Linux programs
- read files
- create or modify files
- invoke shell commands
- access network resources
- invoke privileged commands
- execute a sequence of actions generated from a malicious or manipulated instruction

A prompt-injection attack can therefore move from the AI layer into the operating system.

The security problem investigated by KernelGuard is:

> How can Linux detect, authorize, analyze, and control actions performed by an Agentic AI system at runtime?

KernelGuard addresses this problem by placing a security enforcement point close to the Linux kernel while combining:

1. eBPF/BPF-LSM monitoring
2. Agent process provenance
3. Zero Trust authorization
4. Behavioral Machine Learning
5. Risk fusion
6. Deterministic kernel-level enforcement
7. Controlled Agentic AI and prompt-injection experiments

The central design principle is:

> Machine Learning and AI-based analysis can identify suspicious behavior, but deterministic kernel-level policy remains the final enforcement authority.

This separation is important because an ML model can make mistakes, while a security enforcement mechanism should fail safely.

---

# 2. Overall KernelGuard Architecture

The current KernelGuard prototype follows this logical flow:

```text
                    USER
                      |
                      v
              Agentic AI System
                      |
                      v
              Agent Tools / Actions
                      |
                      v
              Linux Process Creation
                      |
                      v
             BPF-LSM Execution Hook
              bprm_check_security
                      |
          +-----------+-----------+
          |                       |
          v                       v
     Event Collection       ZTA Identity Check
          |                       |
          v                       v
      BPF Ring Buffer       Agent Provenance
          |                       |
          v                       v
   User-Space Reader       Agent-Specific Policy
          |                       |
          +-----------+-----------+
                      |
                      v
             Behavioral Analysis
                      |
                      v
              Machine Learning
                      |
                      v
                Risk Fusion
                      |
                      v
             Security Decision
                      |
              +-------+-------+
              |       |       |
             ALLOW   REVIEW   DENY
              |       |       |
              +-------+-------+
                      |
                      v
              BPF-LSM Enforcement

---

# Technical Architecture and Implementation Details

## 1. Why KernelGuard Is Needed

Traditional security mechanisms are mainly designed to control human users and conventional applications.

Agentic AI introduces a different security problem.

An Agentic AI system can:

- interpret natural-language instructions
- select tools
- read files
- execute programs
- invoke shell commands
- access operating-system resources
- communicate with external services
- perform multiple actions without direct human approval for every step

Therefore, an Agentic AI system can potentially transform a malicious or manipulated instruction into a real operating-system action.

For example:

```text
User Request
     |
     v
Agentic AI
     |
     v
Tool Invocation
     |
     v
Linux Command
     |
     v
Privilege-Sensitive Operation

---

# Technical Architecture and Implementation Details

## 1. Why KernelGuard Is Needed

Traditional security mechanisms are mainly designed to control human users and conventional applications.

Agentic AI introduces a different security problem.

An Agentic AI system can:

- interpret natural-language instructions
- select tools
- read files
- execute programs
- invoke shell commands
- access operating-system resources
- communicate with external services
- perform multiple actions without direct human approval for every step

Therefore, an Agentic AI system can potentially transform a malicious or manipulated instruction into a real operating-system action.

For example:

```text
User Request
     |
     v
Agentic AI
     |
     v
Tool Invocation
     |
     v
Linux Command
     |
     v
Privilege-Sensitive Operation
