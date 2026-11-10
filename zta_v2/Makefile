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
