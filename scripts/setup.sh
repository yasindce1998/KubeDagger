#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    build-essential \
    clang \
    llvm \
    linux-headers-$(uname -r) \
    pkg-config \
    graphviz \
    curl \
    git

GO_VERSION="1.22.5"
if ! command -v go &>/dev/null || ! go version | grep -q "go${GO_VERSION}"; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi

if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
    cat > /etc/profile.d/go.sh <<'EOF'
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
EOF
fi

export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

echo "Setup complete. Go version: $(go version)"
echo "Clang version: $(clang --version | head -1)"
echo "Kernel headers: /lib/modules/$(uname -r)/build"
