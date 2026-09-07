#!/bin/bash
# VIGIL install script
# Compiles eBPF programs, builds the Go binary, and installs system-wide.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
BPF_SRC="${PROJECT_DIR}/internal/ebpf/bpf_src"
BPF_OUT="${BUILD_DIR}/bpf"
BIN_OUT="${BUILD_DIR}/vigil"

echo "╔══════════════════════════════════════════╗"
echo "║  VIGIL — eBPF Endpoint Detection        ║"
echo "║  Install Script                          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check dependencies
echo "[*] Checking dependencies..."

if ! command -v go &>/dev/null; then
    echo "ERROR: Go compiler not found. Install Go 1.24+"
    exit 1
fi

if ! command -v clang &>/dev/null; then
    echo "ERROR: clang not found. Install clang 18+"
    exit 1
fi

if ! command -v bpftool &>/dev/null; then
    echo "ERROR: bpftool not found. Install linux-tools-generic"
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: BTF not available. Kernel must have CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

# Architecture detection (v0.8.0: ARM64 support)
ARCH=$(uname -m)
case "${ARCH}" in
    aarch64|arm64) TARGET_ARCH=arm64 ;;
    *)             TARGET_ARCH=x86 ;;
esac

echo "  Go:      $(go version | awk '{print $3}')"
echo "  clang:   $(clang --version | head -1)"
echo "  bpftool: $(bpftool version | head -1)"
echo "  BTF:     available"
echo "  Arch:    ${ARCH} (__TARGET_ARCH_${TARGET_ARCH})"
echo ""

# Create build directories
mkdir -p "${BPF_OUT}" "${BUILD_DIR}"

# Compile eBPF programs (v0.8.0: all modules, architecture-aware)
echo "[*] Compiling eBPF programs..."
BPF_PROGRAMS="kprobe syscall_arg crossview container dns flow lineage tty integrity"

# vmlinux.h: generate if missing. On ARM64 hosts, regenerate if the shipped
# header was generated from an x86 kernel (user_pt_regs exists only in arm64 BTF).
if [ ! -f "${BPF_SRC}/vmlinux.h" ]; then
    echo "[*] Generating vmlinux.h..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF_SRC}/vmlinux.h"
    echo "  ✓ vmlinux.h generated"
elif [ "${TARGET_ARCH}" = "arm64" ] && ! grep -q "struct user_pt_regs" "${BPF_SRC}/vmlinux.h" 2>/dev/null; then
    echo "[*] vmlinux.h was generated for x86 — regenerating for ARM64 kernel BTF..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF_SRC}/vmlinux.h"
    echo "  ✓ vmlinux.h regenerated for ARM64"
fi

for prog in ${BPF_PROGRAMS}; do
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_${TARGET_ARCH} \
        -I"${BPF_SRC}" \
        -I/usr/include/bpf \
        -c "${BPF_SRC}/vigil_${prog}.c" \
        -o "${BPF_OUT}/vigil_${prog}.o"

    if [ $? -ne 0 ]; then
        echo "ERROR: eBPF compilation failed for vigil_${prog}.c"
        exit 1
    fi

    echo "  ✓ vigil_${prog}.o compiled"
done

# Build Go binary
echo "[*] Building VIGIL binary..."
cd "${PROJECT_DIR}"

# Download dependencies
go mod tidy

# Build with version info
VERSION="0.1.0"
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

go build \
    -ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.commit=${COMMIT}" \
    -o "${BIN_OUT}" \
    ./cmd/vigil/

if [ $? -ne 0 ]; then
    echo "ERROR: Go build failed"
    exit 1
fi

echo "  ✓ vigil binary built"

# Install
echo "[*] Installing..."

# Binary
install -m 0755 "${BIN_OUT}" /usr/local/bin/vigil
echo "  ✓ /usr/local/bin/vigil"

# eBPF objects (all modules)
mkdir -p /usr/local/lib/vigil
for prog in ${BPF_PROGRAMS}; do
    install -m 0644 "${BPF_OUT}/vigil_${prog}.o" /usr/local/lib/vigil/
done
echo "  ✓ /usr/local/lib/vigil/ (${BPF_PROGRAMS})"

# Config directory
mkdir -p /etc/vigil
echo "  ✓ /etc/vigil/"

# Data directory
mkdir -p /var/lib/vigil
chmod 0700 /var/lib/vigil
echo "  ✓ /var/lib/vigil/"

# Log directory
mkdir -p /var/log/vigil
chmod 0755 /var/log/vigil
echo "  ✓ /var/log/vigil/"

# Systemd service
install -m 0644 "${PROJECT_DIR}/configs/vigil.service" /etc/systemd/system/
systemctl daemon-reload
echo "  ✓ systemd service installed"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  VIGIL installed successfully            ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Usage:"
echo "  sudo systemctl start vigil         # Start VIGIL"
echo "  sudo systemctl enable vigil        # Enable on boot"
echo "  sudo journalctl -u vigil -f        # View logs"
echo "  sudo systemctl reload vigil         # Reload baseline (SIGHUP)"
echo ""
echo "First run will enter learning phase (10 min default)."
echo "After learning, VIGIL automatically switches to detection mode."