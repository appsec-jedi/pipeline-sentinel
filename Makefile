CLANG ?= clang
GO ?= go
BPFTOOL ?= bpftool
BINARY_NAME=pipeline-sentinel

EBPF_DIR := ebpf
HEADERS_DIR := $(EBPF_DIR)/headers
EBPF_SRC := $(EBPF_DIR)/bpf.c
EBPF_OUT := $(EBPF_DIR)/bpf_bpfel.o
VMLINUX_H := $(HEADERS_DIR)/vmlinux.h

.PHONY: all clean build build-ebpf generate-vmlinux generate-go

all: build

build: generate-go
	$(GO) build -o $(BINARY_NAME) main.go bpf_bpfel.go

generate-go: build-ebpf
	@echo "--- Generating Go bindings ---"
	$(GO) generate

build-ebpf: generate-vmlinux
	@echo "--- Building eBPF program ---"
	$(CLANG) -g -O2 -target bpf -c $(EBPF_SRC) -o $(EBPF_OUT) -I $(HEADERS_DIR)

generate-vmlinux:
	@echo "--- Generating vmlinux.h ---"
	@mkdir -p $(HEADERS_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

clean:
	@echo "--- Cleaning up ---"
	rm -f $(EBPF_OUT) bpf_bpfel.go bpf_bpfel_x86.go $(BINARY_NAME)
	rm -rf $(HEADERS_DIR)