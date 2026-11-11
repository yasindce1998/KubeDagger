FROM golang:1.26.0-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY scripts/install-bpftool.sh scripts/install-bpftool.sh
RUN bash scripts/install-bpftool.sh
COPY go.mod go.sum ./
RUN go mod download
ENV CGO_ENABLED=0
COPY . .

# Generate this header on the Linux host with `make generate-vmlinux` first.
# Docker builds normally cannot read the host's /sys/kernel/btf/vmlinux.
RUN test -s ebpf/include/vmlinux.h || (echo 'Run make generate-vmlinux on the host before docker build' >&2; exit 1)
RUN make build-ebpf
RUN make build-rootkit build-client build-webapp

FROM ubuntu:jammy

RUN apt-get update && apt-get install -y \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/bin/ /usr/local/bin/
COPY --from=builder /src/pkg/assets/bin/ /opt/kubedagger/ebpf/

ENTRYPOINT ["kubedagger"]
