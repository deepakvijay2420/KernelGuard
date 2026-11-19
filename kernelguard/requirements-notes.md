# Dependencies

## Required for the controller and tests

```bash
python3 -m pip install PyYAML
```

## Required for the eBPF build

Install system packages for clang/LLVM with the BPF target, GCC, libbpf development headers and bpftool using the package manager for your Linux distribution.

## Optional agent integration

The example LangChain/Gemini agent requires its LangChain and Google GenAI integration packages and a user-provided `GOOGLE_API_KEY`. Never commit the API key.

Behavioural-analysis and ML dependencies are not required because those components are not part of the current implementation.
