# KubeDagger

<p align="center">
  <img src="https://github.com/yasindce1998/KubeDagger/blob/master/logo/logo-removebg-preview.png?raw=true" alt="KubeDagger"/>
</p>

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

An eBPF-based security research tool that demonstrates offensive techniques including network discovery, file system monitoring, process hiding, and container breakouts.

## Disclaimer

This project is provided for **educational purposes only**. Do not use these tools to violate the law. The author is not responsible for any illegal action. Misuse of the provided information can result in criminal charges.

## Requirements

- Linux kernel 5.4+ with eBPF support (BTF-enabled for CO-RE portability)
- Go 1.25+
- Kernel headers installed in `lib/modules/$(uname -r)`
- clang & llvm 11+
- [Graphviz](https://graphviz.org/) (for network graph generation)

## Build

```shell
make
```

To install the client to `/usr/bin/`:

```shell
make install_client
```

## Quick Start

```shell
# Check prerequisites
./scripts/check-prereqs.sh

# Build
make

# Start the server (requires root)
sudo ./bin/kubedagger -i eth0 -e eth0

# Use the client
kubedagger-client -h
```

> **For full usage instructions, see [USAGE.md](USAGE.md)**

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
