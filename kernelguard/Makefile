# KernelGuard unified build: BPF-LSM object + user-space event reader.
# Run from this directory: make, make test, make clean.
# Requires clang/LLVM with BPF target, gcc, libbpf-dev and bpftool.

CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= $(shell command -v bpftool || echo /usr/sbin/bpftool)
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

# The committed CO-RE vmlinux.h is currently sourced from the repository ebpf/
# directory. A host-specific header generated with "make vmlinux" takes priority.
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf -I../ebpf

all: build/kg_zta.bpf.o build/kg_events

build:
	mkdir -p build

build/kg_zta.bpf.o: bpf/kg_zta.bpf.c bpf/kg_common.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/kg_events: tools/kg_events.c bpf/kg_common.h | build
	$(CC) -O2 -Wall -Ibpf $< -lbpf -o $@

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

test:
	python3 -m unittest discover -s tests -v

clean:
	rm -rf build

.PHONY: all test vmlinux clean
