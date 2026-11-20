ROOT := ../..
BPF_DIR := $(ROOT)/ebpf/zta
BPF_SRC := $(BPF_DIR)/zta_enforcer.bpf.c
BPF_OBJ := $(BPF_DIR)/zta_enforcer.bpf.o
BPF_SKEL := $(BPF_DIR)/zta_enforcer.skel.h
VMLINUX := $(BPF_DIR)/vmlinux.h
CONTROLLER := ./zta_controller

ARCH := $(shell uname -m)
BPF_ARCH := $(if $(filter x86_64,$(ARCH)),x86,$(ARCH))
CLANG := clang
CC := gcc
BPFTOOL := bpftool

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -I$(BPF_DIR) -I/usr/include/$(ARCH)-linux-gnu
USER_CFLAGS := -O2 -g -Wall -Wextra
USER_LIBS := $(shell pkg-config --cflags --libs libbpf yaml-0.1)

.PHONY: all clean check

all: $(CONTROLLER)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

$(CONTROLLER): zta_controller.c $(BPF_SKEL)
	$(CC) $(USER_CFLAGS) zta_controller.c -o $(CONTROLLER) $(USER_LIBS)

check:
	pkg-config --exists libbpf yaml-0.1
	$(CLANG) --print-targets | grep -i bpf
	$(BPFTOOL) version

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(CONTROLLER)
