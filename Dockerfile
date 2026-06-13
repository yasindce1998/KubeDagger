FROM ubuntu:jammy AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    linux-headers-generic \
    pkg-config \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

ARG GO_VERSION=1.22.5
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:$PATH"

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN make build-ebpf
RUN make build-rootkit build-client build-webapp

FROM ubuntu:jammy

RUN apt-get update && apt-get install -y \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/bin/ /usr/local/bin/
COPY --from=builder /src/pkg/assets/bin/ /opt/kubedagger/ebpf/

ENTRYPOINT ["kubedagger"]
