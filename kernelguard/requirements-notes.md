# Python dependencies for optional KernelGuard components

PyYAML is required by the policy controller and tests.
NumPy and pandas are required by behavioural feature extraction.
joblib and pandas are required by the ML inference wrapper.
LangChain and langchain-google-genai are required by the Gemini agent example.

Install only the components needed for your experiment:

```bash
python3 -m pip install PyYAML numpy pandas joblib
python3 -m pip install langchain langchain-google-genai
```

The eBPF build additionally requires system packages such as clang/LLVM, gcc, libbpf development headers and bpftool. Those are not Python packages.
