#!/bin/bash

set -e

BPF_DIR="/home/deepak/kernelguard/ebpf"
BPF_OBJ="$BPF_DIR/exec_monitor.bpf.o"

BPF_FS="/sys/fs/bpf"
PROGRAM_PIN="$BPF_FS/kernelguard_test"
RINGBUF_PIN="$BPF_FS/kernelguard_events"

BPFTool="/usr/sbin/bpftool"

echo "[KernelGuard] Starting..."

# Make sure BPF filesystem is mounted
mkdir -p "$BPF_FS"

if ! mountpoint -q "$BPF_FS"; then
    mount -t bpf bpf "$BPF_FS"
fi

# Remove old pins
rm -f "$PROGRAM_PIN" 2>/dev/null || true
rm -f "$RINGBUF_PIN" 2>/dev/null || true

echo "[KernelGuard] Loading BPF-LSM program..."

"$BPFTool" prog load "$BPF_OBJ"     "$PROGRAM_PIN"     type lsm autoattach

echo "[KernelGuard] BPF-LSM program loaded"

# Find ring buffer map called 'events'
MAP_ID=$("$BPFTool" map show |     awk '$2 == "ringbuf" && $3 == "name" && $4 == "events" {
        gsub(":", "", $1);
        print $1;
        exit
    }')

if [ -z "$MAP_ID" ]; then
    echo "[KernelGuard] ERROR: events ring buffer not found"
    exit 1
fi

echo "[KernelGuard] Ring buffer map ID: $MAP_ID"

# Pin ring buffer
"$BPFTool" map pin id "$MAP_ID" "$RINGBUF_PIN"

echo "[KernelGuard] Ring buffer pinned"
echo "[KernelGuard] Startup complete"
