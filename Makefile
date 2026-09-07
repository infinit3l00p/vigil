# VIGIL — eBPF Endpoint Detection & Response
# v0.8.0: ARM64 support — architecture-aware BPF compilation + cross-compile.

GO ?= go
ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
TARGET_ARCH := arm64
else
TARGET_ARCH := x86
endif

BPF_SRC := internal/ebpf/bpf_src
BPF_OUT := build/bpf
BPF_PROGRAMS := kprobe syscall_arg crossview container dns flow lineage tty integrity

.PHONY: build bpf arm64 test vet clean

# Build the Go binary for the CURRENT architecture (pure Go, no cgo).
build:
	CGO_ENABLED=0 $(GO) build -o build/vigil ./cmd/vigil/

# Compile eBPF objects for the CURRENT kernel architecture.
# vmlinux.h is generated from the RUNNING kernel's BTF — run this ON the
# target host. On ARM64 the shipped x86 vmlinux.h is auto-regenerated
# (detected via user_pt_regs, which exists only in arm64 BTF).
bpf:
	@mkdir -p $(BPF_OUT)
	@if [ ! -f $(BPF_SRC)/vmlinux.h ]; then \
		echo "[*] Generating vmlinux.h from /sys/kernel/btf/vmlinux..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_SRC)/vmlinux.h; \
	fi
	@if [ "$(TARGET_ARCH)" = "arm64" ] && ! grep -q "struct user_pt_regs" $(BPF_SRC)/vmlinux.h 2>/dev/null; then \
		echo "[*] vmlinux.h is x86-generated — regenerating for ARM64 kernel BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_SRC)/vmlinux.h; \
	fi
	@for prog in $(BPF_PROGRAMS); do \
		echo "[*] vigil_$$prog.c"; \
		clang -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
			-I$(BPF_SRC) -I/usr/include/bpf \
			-c $(BPF_SRC)/vigil_$$prog.c -o $(BPF_OUT)/vigil_$$prog.o || exit 1; \
	done
	@echo "[+] eBPF objects -> $(BPF_OUT)/ (arch=$(TARGET_ARCH))"

# Cross-compile the ARM64 userspace binary (pure Go, no cgo).
# Deploy it together with BPF objects built ON the ARM64 host (make bpf there).
arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o build/vigil-linux-arm64 ./cmd/vigil/
	@echo "[+] -> build/vigil-linux-arm64 (deploy with BPF objects built on the ARM64 host)"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf build/