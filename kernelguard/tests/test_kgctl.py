"""
Unit tests for the unified KernelGuard controller.
They need no root, BPF attachment or network:
    cd kernelguard && make test

The layout test compiles kg_common.h and compares C structure sizes
with the byte layouts packed by kgctl.py.
"""