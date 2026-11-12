# KernelGuard ZTA v2 build
#
#   make            build BPF object + events reader
#   make test       run unit tests (no root, no kernel features needed)
#   make vmlinux    (optional) regenerate bpf/vmlinux.h from THIS kernel's BTF
#   make clean
#
# Requires: clang, libbpf-dev (headers + -lbpf), and for `make vmlinux` bpftool.

CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= $(shell command -v bpftool || echo /usr/sbin/bpftool)
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

# bpf/ first so a freshly generated bpf/vmlinux.h wins; ../ebpf is the repo's committed copy
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
