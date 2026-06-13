#!/bin/bash
#
# KubeDagger Prerequisites Check
# Run this script to verify your system meets all requirements.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    WARN=$((WARN + 1))
}

echo "============================================"
echo "  KubeDagger Prerequisites Check"
echo "============================================"
echo ""

# --- OS Check ---
echo "[*] Operating System"
if [ "$(uname -s)" = "Linux" ]; then
    pass "Linux detected ($(uname -r))"
else
    fail "Linux required (detected: $(uname -s))"
fi
echo ""

# --- Kernel Version ---
echo "[*] Kernel Version (5.4+ required for eBPF)"
if [ "$(uname -s)" = "Linux" ]; then
    KVER=$(uname -r | cut -d. -f1-2)
    KMAJOR=$(echo "$KVER" | cut -d. -f1)
    KMINOR=$(echo "$KVER" | cut -d. -f2)
    if [ "$KMAJOR" -gt 5 ] || { [ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -ge 4 ]; }; then
        pass "Kernel $KVER >= 5.4"
    else
        fail "Kernel $KVER < 5.4 (eBPF features may not work)"
    fi
else
    fail "Cannot check kernel version (not Linux)"
fi
echo ""

# --- Kernel Headers ---
echo "[*] Kernel Headers"
if [ -d "/lib/modules/$(uname -r)/build" ]; then
    pass "Kernel headers found at /lib/modules/$(uname -r)/build"
elif [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
    pass "Kernel headers found at /usr/src/linux-headers-$(uname -r)"
else
    fail "Kernel headers not found (install linux-headers-$(uname -r))"
fi
echo ""

# --- eBPF Support ---
echo "[*] eBPF Support"
if [ -d "/sys/fs/bpf" ]; then
    pass "BPF filesystem mounted (/sys/fs/bpf)"
else
    warn "BPF filesystem not mounted (try: mount -t bpf bpf /sys/fs/bpf)"
fi

if [ -f "/proc/config.gz" ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
        pass "CONFIG_BPF=y in kernel config"
    else
        warn "Cannot confirm CONFIG_BPF (check /proc/config.gz)"
    fi
elif [ -f "/boot/config-$(uname -r)" ]; then
    if grep -q "CONFIG_BPF=y" "/boot/config-$(uname -r)"; then
        pass "CONFIG_BPF=y in kernel config"
    fi
    if grep -q "CONFIG_BPF_SYSCALL=y" "/boot/config-$(uname -r)"; then
        pass "CONFIG_BPF_SYSCALL=y in kernel config"
    else
        fail "CONFIG_BPF_SYSCALL not enabled"
    fi
    if grep -q "CONFIG_BPF_JIT=y" "/boot/config-$(uname -r)"; then
        pass "CONFIG_BPF_JIT=y (JIT compilation enabled)"
    else
        warn "CONFIG_BPF_JIT not enabled (performance may be reduced)"
    fi
else
    warn "Cannot locate kernel config to verify BPF support"
fi
echo ""

# --- Go ---
echo "[*] Go Compiler (1.22+ required)"
if command -v go &>/dev/null; then
    GO_VER=$(go version | grep -oP '\d+\.\d+' | head -1)
    GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
    if [ "$GO_MAJOR" -gt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 22 ]; }; then
        pass "Go $GO_VER >= 1.22 ($(go env GOROOT))"
    else
        fail "Go $GO_VER < 1.22 (upgrade required)"
    fi
else
    fail "Go not found in PATH"
fi
echo ""

# --- Clang/LLVM ---
echo "[*] Clang/LLVM (11+ required for eBPF compilation)"
if command -v clang &>/dev/null; then
    CLANG_VER=$(clang --version | head -1 | grep -oP '\d+' | head -1)
    if [ "$CLANG_VER" -ge 11 ]; then
        pass "clang $CLANG_VER >= 11"
    else
        fail "clang $CLANG_VER < 11"
    fi
else
    fail "clang not found in PATH"
fi

if command -v llc &>/dev/null; then
    LLC_VER=$(llc --version | grep -oP 'LLVM version \K\d+' | head -1)
    if [ -n "$LLC_VER" ] && [ "$LLC_VER" -ge 11 ]; then
        pass "llc (LLVM $LLC_VER)"
    else
        pass "llc found"
    fi
else
    fail "llc not found in PATH (install llvm)"
fi
echo ""

# --- Make ---
echo "[*] Build Tools"
if command -v make &>/dev/null; then
    pass "make found ($(make --version | head -1))"
else
    fail "make not found"
fi

if command -v gcc &>/dev/null; then
    pass "gcc found ($(gcc --version | head -1))"
else
    warn "gcc not found (may be needed for cgo)"
fi
echo ""

# --- Optional Tools ---
echo "[*] Optional Tools"
if command -v dot &>/dev/null; then
    pass "graphviz (dot) found"
else
    warn "graphviz not found (needed for network graph generation)"
fi

if command -v kubectl &>/dev/null; then
    pass "kubectl found ($(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1))"
else
    warn "kubectl not found (needed for K8s discovery features)"
fi

if command -v docker &>/dev/null; then
    pass "docker found"
else
    warn "docker not found (needed for Docker override features)"
fi
echo ""

# --- Permissions ---
echo "[*] Permissions"
if [ "$(id -u)" -eq 0 ]; then
    pass "Running as root"
else
    warn "Not running as root (kubedagger server requires root or CAP_BPF+CAP_NET_ADMIN)"
fi

if [ "$(id -u)" -ne 0 ]; then
    if command -v capsh &>/dev/null; then
        if capsh --print 2>/dev/null | grep -q "cap_bpf"; then
            pass "CAP_BPF available"
        else
            warn "CAP_BPF not in current capabilities"
        fi
    fi
fi
echo ""

# --- Summary ---
echo "============================================"
echo "  Summary"
echo "============================================"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Warnings:${NC} $WARN"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}All critical checks passed! Ready to build.${NC}"
    echo ""
    echo "  Next steps:"
    echo "    make"
    echo "    sudo ./bin/kubedagger -i <interface> -e <interface>"
    echo ""
    exit 0
else
    echo -e "  ${RED}$FAIL critical check(s) failed. Fix the issues above before building.${NC}"
    echo ""
    exit 1
fi
