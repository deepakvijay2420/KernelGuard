#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$HOME/kernelguard"
V2="$ROOT/zta_v2"
LIBDIR="$HOME/.local/lib64"
INCLUDEDIR="$HOME/.local/include"
LIBBPF="$LIBDIR/libbpf.so.1.4.0"

echo "=========================================="
echo " KERNELGUARD V2 - LIBBPF AND BTF FIX"
echo "=========================================="

cd "$ROOT"

# 1. Verify local libbpf
echo
echo "[1/7] Checking local libbpf..."

if [[ ! -f "$LIBBPF" ]]; then
    echo "ERROR: Local libbpf 1.4.0 not found: $LIBBPF"
    exit 1
fi

if [[ ! -f "$INCLUDEDIR/bpf/libbpf.h" ]]; then
    echo "ERROR: Local libbpf headers not found."
    exit 1
fi

ln -sfn libbpf.so.1.4.0 "$LIBDIR/libbpf.so.1"

echo "Local libbpf:"
ls -l "$LIBDIR"/libbpf.so*

# 2. Verify kernel BTF
echo
echo "[2/7] Checking kernel BTF..."

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: /sys/kernel/btf/vmlinux is not readable."
    exit 1
fi

if ! bpftool btf dump file /sys/kernel/btf/vmlinux format raw >/dev/null; then
    echo "ERROR: bpftool cannot parse kernel BTF."
    exit 1
fi

echo "Kernel BTF is readable and parseable."

# 3. Verify BPF LSM
echo
echo "[3/7] Checking BPF LSM..."

if ! grep -qw bpf /sys/kernel/security/lsm; then
    echo "ERROR: BPF LSM is not enabled."
    cat /sys/kernel/security/lsm
    exit 1
fi

echo "BPF LSM is enabled."

# 4. Replace Makefile with explicit local libbpf linking
echo
echo "[4/7] Updating zta_v2 Makefile..."

cat > "$V2/Makefile" <<'MAKEFILE'
CLANG := clang
CC := gcc
BPFTOOL := bpftool

ARCH := $(shell uname -m)
BPF_ARCH := $(if $(filter x86_64,$(ARCH)),x86,$(ARCH))

BPF_SRC := bpf/kg_zta.bpf.c
BPF_OBJ := build/kg_zta.bpf.o
READER_SRC := tools/kg_events.c
READER := build/kg_events
VMLINUX := bpf/vmlinux.h

LOCAL_LIBDIR := $(HOME)/.local/lib64
LOCAL_INCLUDEDIR := $(HOME)/.local/include
LOCAL_LIBBPF := $(LOCAL_LIBDIR)/libbpf.so.1.4.0

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -I./bpf -I/usr/include/$(ARCH)-linux-gnu

USER_CFLAGS := -O2 -g -I$(LOCAL_INCLUDEDIR) -I./bpf
USER_LIBS := $(LOCAL_LIBBPF) -lelf -lz
USER_LIBS += -Wl,-rpath,$(LOCAL_LIBDIR)

.PHONY: all clean inspect

all: $(BPF_OBJ) $(READER)

$(BPF_OBJ): $(BPF_SRC) bpf/kg_common.h $(VMLINUX)
	mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

$(READER): $(READER_SRC) bpf/kg_common.h
	mkdir -p build
	$(CC) $(USER_CFLAGS) $(READER_SRC) -o $(READER) $(USER_LIBS)

inspect: $(BPF_OBJ)
	$(BPFTOOL) btf dump file $(BPF_OBJ) format raw
	llvm-objdump -h $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ) $(READER)
MAKEFILE

# 5. Rebuild
echo
echo "[5/7] Rebuilding KernelGuard v2..."

make -C "$V2" clean
make -C "$V2"

# 6. Verify actual runtime library
echo
echo "[6/7] Checking linked libraries..."

ldd "$V2/build/kg_events"

if ! ldd "$V2/build/kg_events" | grep -q "$LIBDIR/libbpf.so.1"; then
    echo
    echo "ERROR: Reader is NOT using local libbpf 1.4.0."
    echo "Do not run KernelGuard yet."
    exit 1
fi

if ldd "$V2/build/kg_events" | grep -q 'libbpf.so.0'; then
    echo "ERROR: Old system libbpf.so.0 is still being loaded."
    exit 1
fi

echo "SUCCESS: Reader is linked to local libbpf."

# 7. Verify generated files
echo
echo "[7/7] Checking generated files..."

file "$V2/build/kg_zta.bpf.o"
file "$V2/build/kg_events"

echo
echo "=========================================="
echo " BUILD AND LIBRARY VERIFICATION PASSED"
echo "=========================================="
echo
echo "Starting KernelGuard v2..."
echo "Press Ctrl+C to stop."
echo

cd "$V2"
sudo env LD_LIBRARY_PATH="$LIBDIR" ./build/kg_events
