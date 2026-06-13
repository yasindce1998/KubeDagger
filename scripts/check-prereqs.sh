#!/bin/bash
#
# KubeDagger Prerequisites Check & Install
# Run this script to verify your system meets all requirements.
# Use --install to automatically install missing packages.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
INSTALL_MODE=false
MISSING_PKGS=()

if [ "$1" = "--install" ] || [ "$1" = "-i" ]; then
    INSTALL_MODE=true
fi

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

info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
}

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
    else
        PKG_MANAGER="unknown"
    fi
}

install_pkg() {
    local pkg_apt="$1"
    local pkg_dnf="$2"
    local pkg_pacman="$3"
    local pkg_zypper="$4"

    if [ "$INSTALL_MODE" != true ]; then
        return 1
    fi

    case "$PKG_MANAGER" in
        apt)
            info "Installing: $pkg_apt"
            sudo apt-get install -y $pkg_apt
            ;;
        dnf)
            info "Installing: $pkg_dnf"
            sudo dnf install -y $pkg_dnf
            ;;
        yum)
            info "Installing: $pkg_dnf"
            sudo yum install -y $pkg_dnf
            ;;
        pacman)
            info "Installing: $pkg_pacman"
            sudo pacman -S --noconfirm $pkg_pacman
            ;;
        zypper)
            info "Installing: $pkg_zypper"
            sudo zypper install -y $pkg_zypper
            ;;
        *)
            warn "Unknown package manager. Install manually: $pkg_apt"
            return 1
            ;;
    esac
}

detect_pkg_manager

echo "============================================"
echo "  KubeDagger Prerequisites Check"
if [ "$INSTALL_MODE" = true ]; then
    echo "  Mode: CHECK + INSTALL"
    echo "  Package manager: $PKG_MANAGER"
else
    echo "  Mode: CHECK ONLY (use --install to fix)"
fi
echo "============================================"
echo ""

# --- OS Check ---
echo "[*] Operating System"
if [ "$(uname -s)" = "Linux" ]; then
    pass "Linux detected ($(uname -r))"
else
    fail "Linux required (detected: $(uname -s))"
    echo ""
    echo -e "  ${RED}KubeDagger requires Linux. Cannot continue.${NC}"
    exit 1
fi
echo ""

# --- Kernel Version ---
echo "[*] Kernel Version (5.4+ required for eBPF)"
KVER=$(uname -r | cut -d. -f1-2)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJOR" -gt 5 ] || { [ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -ge 4 ]; }; then
    pass "Kernel $KVER >= 5.4"
else
    fail "Kernel $KVER < 5.4 (eBPF features may not work)"
    if [ "$INSTALL_MODE" = true ]; then
        warn "Kernel upgrade must be done manually (apt upgrade linux-image / dnf upgrade kernel)"
    fi
fi
echo ""

# --- Kernel Headers ---
echo "[*] Kernel Headers"
if [ -d "/lib/modules/$(uname -r)/build" ] || [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
    pass "Kernel headers found"
else
    fail "Kernel headers not found"
    if [ "$INSTALL_MODE" = true ]; then
        install_pkg \
            "linux-headers-$(uname -r)" \
            "kernel-devel-$(uname -r)" \
            "linux-headers" \
            "kernel-devel"
    fi
fi
echo ""

# --- eBPF Support ---
echo "[*] eBPF Support"
if [ -d "/sys/fs/bpf" ]; then
    pass "BPF filesystem mounted (/sys/fs/bpf)"
else
    warn "BPF filesystem not mounted"
    if [ "$INSTALL_MODE" = true ]; then
        info "Mounting BPF filesystem..."
        sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null && pass "Mounted /sys/fs/bpf" || warn "Failed to mount (may need root)"
    fi
fi

if [ -f "/proc/config.gz" ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
        pass "CONFIG_BPF=y in kernel config"
    else
        warn "Cannot confirm CONFIG_BPF (check /proc/config.gz)"
    fi
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF_SYSCALL=y"; then
        pass "CONFIG_BPF_SYSCALL=y in kernel config"
    fi
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF_JIT=y"; then
        pass "CONFIG_BPF_JIT=y (JIT compilation enabled)"
    else
        warn "CONFIG_BPF_JIT not enabled (performance may be reduced)"
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
        if [ "$INSTALL_MODE" = true ]; then
            info "Downloading Go 1.22..."
            curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -o /tmp/go1.22.tar.gz
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf /tmp/go1.22.tar.gz
            rm /tmp/go1.22.tar.gz
            export PATH=/usr/local/go/bin:$PATH
            pass "Go 1.22 installed to /usr/local/go (add to PATH)"
        fi
    fi
else
    fail "Go not found in PATH"
    if [ "$INSTALL_MODE" = true ]; then
        info "Downloading Go 1.22..."
        curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -o /tmp/go1.22.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go1.22.tar.gz
        rm /tmp/go1.22.tar.gz
        export PATH=/usr/local/go/bin:$PATH
        if command -v go &>/dev/null; then
            pass "Go installed to /usr/local/go"
            info "Add to your shell: export PATH=/usr/local/go/bin:\$PATH"
        else
            fail "Go installation failed"
        fi
    fi
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
        if [ "$INSTALL_MODE" = true ]; then
            install_pkg "clang-14 llvm-14" "clang llvm" "clang llvm" "clang llvm"
        fi
    fi
else
    fail "clang not found in PATH"
    if [ "$INSTALL_MODE" = true ]; then
        install_pkg "clang-14 llvm-14" "clang llvm" "clang llvm" "clang llvm"
    fi
fi

if command -v llc &>/dev/null; then
    LLC_VER=$(llc --version 2>/dev/null | grep -oP 'LLVM version \K\d+' | head -1)
    if [ -n "$LLC_VER" ] && [ "$LLC_VER" -ge 11 ]; then
        pass "llc (LLVM $LLC_VER)"
    else
        pass "llc found"
    fi
else
    fail "llc not found in PATH (install llvm)"
    if [ "$INSTALL_MODE" = true ]; then
        install_pkg "llvm-14" "llvm" "llvm" "llvm"
    fi
fi
echo ""

# --- Build Tools ---
echo "[*] Build Tools"
if command -v make &>/dev/null; then
    pass "make found ($(make --version | head -1))"
else
    fail "make not found"
    if [ "$INSTALL_MODE" = true ]; then
        install_pkg "build-essential" "make gcc" "base-devel" "make gcc"
    fi
fi

if command -v gcc &>/dev/null; then
    pass "gcc found ($(gcc --version | head -1))"
else
    warn "gcc not found (may be needed for cgo)"
    if [ "$INSTALL_MODE" = true ]; then
        install_pkg "gcc" "gcc" "gcc" "gcc"
    fi
fi
echo ""

# --- Optional Tools ---
echo "[*] Optional Tools"
if command -v dot &>/dev/null; then
    pass "graphviz (dot) found"
else
    warn "graphviz not found (needed for network graph generation)"
    if [ "$INSTALL_MODE" = true ]; then
        install_pkg "graphviz" "graphviz" "graphviz" "graphviz"
    fi
fi

if command -v kubectl &>/dev/null; then
    pass "kubectl found ($(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1))"
else
    warn "kubectl not found (needed for K8s discovery features)"
    if [ "$INSTALL_MODE" = true ]; then
        info "Installing kubectl..."
        curl -sLO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
        rm -f kubectl
        command -v kubectl &>/dev/null && pass "kubectl installed" || warn "kubectl installation failed"
    fi
fi

if command -v docker &>/dev/null; then
    pass "docker found"
else
    warn "docker not found (needed for Docker override features)"
    if [ "$INSTALL_MODE" = true ]; then
        info "Docker installation is complex. See: https://docs.docker.com/engine/install/"
        warn "Skipping Docker auto-install (follow official docs)"
    fi
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
echo -e "  ${GREEN}Passed:${NC}   $PASS"
echo -e "  ${RED}Failed:${NC}   $FAIL"
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
    if [ "$INSTALL_MODE" != true ]; then
        echo -e "  ${RED}$FAIL critical check(s) failed.${NC}"
        echo -e "  Run with ${BLUE}--install${NC} to attempt automatic installation:"
        echo ""
        echo "    sudo ./scripts/check-prereqs.sh --install"
        echo ""
    else
        echo -e "  ${RED}$FAIL critical check(s) could not be resolved.${NC}"
        echo "  Please fix the remaining issues manually."
        echo ""
    fi
    exit 1
fi
